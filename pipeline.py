"""单 URL 全自动分析编排：预检 → 预筛 → (黑名单跳过) 沙箱 agent → 研判 → 报告。"""
from __future__ import annotations

import logging
from pathlib import Path

import yaml

from agent.react_loop import ReActLoop
from analyze.judge import Judge
from analyze.signals import merge_llm_dimensions, rule_score
from llm.factory import create_provider_with_retry_log
from precheck.static_filter import static_prefilter
from precheck.url_guard import UrlRejectedError, guard
from report.html_report import render_report
from sandbox.browser import SandboxBrowser
from sandbox.tools import ToolBox
from storage import db

log = logging.getLogger(__name__)

_ROOT = Path(__file__).parent


def load_config(path: str | None = None) -> dict:
    cfg_path = Path(path) if path else _ROOT / "config.yaml"
    with open(cfg_path, encoding="utf-8") as f:
        return yaml.safe_load(f)


def analyze_url(raw_url: str, cfg: dict | None = None) -> dict:
    """主流程。返回 {"ok", "task_id", "report_path", "report", "error"}。"""
    cfg = cfg or load_config()
    db_path = str(_ROOT / cfg["storage"]["db_path"])
    evidence_dir = str(_ROOT / cfg["storage"]["evidence_dir"])
    report_dir = str(_ROOT / cfg["storage"]["report_dir"])
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)

    task_id = db.create_task(db_path, raw_url, "")
    db.update_task(db_path, task_id, status="running")

    try:
        # ---------- 1. 安全预检 ----------
        url, domain, _ip = guard(raw_url)
        db.update_task(db_path, task_id, domain=domain)
        log.info("[1/5] 预检通过: %s (主域 %s)", url, domain)

        # ---------- 1.5 诈骗网址库优先查询（命中即拦截，节省 LLM token）----------
        hit = db.fraud_db_hit(db_path, url, domain)
        if hit:
            log.info("[1.5/5] 诈骗库命中(id=%s, source=%s, 历史拦截 %s 次)，"
                     "直接拦截", hit["id"], hit["source"], hit["hit_count"])
            return _db_blocked_result(db_path, cfg, task_id, url, domain,
                                      hit, evidence_dir, report_dir)

        # ---------- 2. 静态预筛 ----------
        prefilter = static_prefilter(url, domain,
                                     cfg.get("precheck", {}))
        log.info("[2/5] 预筛完成: score=%s blacklist=%s",
                 prefilter["risk_score"], prefilter["blacklist_hit"])

        agent_result = {"rounds": 0, "summary": "（黑名单命中，跳过沙箱探测）",
                        "fill_feedback": [], "redirect_chain": []}
        screenshots: list[str] = []
        tech_signals: dict = {}
        isolation_level = "N/A"

        # ---------- 3. 沙箱 Agent（黑名单命中则跳过）----------
        if not prefilter["blacklist_hit"]:
            with SandboxBrowser(cfg, evidence_dir) as sb:
                isolation_level = sb.isolation
                db.update_task(db_path, task_id, isolation_level=isolation_level)
                log.info("[3/5] 沙箱就绪（隔离级别 %s）", isolation_level)
                toolbox = ToolBox(sb, db_path, task_id,
                                  cfg.get("analyze", {}).get(
                                      "page_text_max_chars", 3000))
                # §8.2 约束 1：allowlist = 目标域名（静态资源域先放行收集再收紧亦可，
                # demo 中导航由工具内预检兜底，这里记录但不预锁，避免静态资源全被拦）
                provider = create_provider_with_retry_log(
                    cfg["llm"], db_path)
                agent_cfg = cfg["llm"].get("agent", {})
                loop = ReActLoop(provider, toolbox,
                                 max_rounds=agent_cfg.get("max_tool_rounds", 8),
                                 temperature=agent_cfg.get("temperature", 0.2),
                                 task_id=task_id)
                agent_result = loop.run(url)

                # 技术信号提取
                final_url = sb.page.url
                forms = toolbox.dispatch("get_forms", {})  # 已有则复用信号
                import json as _json
                try:
                    forms_data = _json.loads(forms).get("forms", [])
                except Exception:  # noqa: BLE001
                    forms_data = []
                page_domain = final_url.split("//", 1)[-1].split("/", 1)[0]
                tech_signals = {
                    "form_action_third_party": any(
                        not f["action_domain_matches_page"] for f in forms_data),
                    "password_outside_login": any(
                        fl.get("is_password") for f in forms_data
                        for fl in f["fields"])
                        and "login" not in final_url.lower()
                        and "signin" not in final_url.lower(),
                    "http_form": final_url.startswith("http://"),
                    "redirect_jumps": len(sb.redirect_chain) - 1,
                }
                # 关键截图：agent 已截过则复用证据库，否则补一张
                ev = db.list_evidence(db_path, task_id)
                screenshots = [e["content"] for e in ev
                               if e["kind"] == "screenshot"]
                if not screenshots and sb.page:
                    screenshots = [sb.screenshot(full_page=True)]
                    db.add_evidence(db_path, task_id, "screenshot",
                                    "整页截图", screenshots[0])
        else:
            isolation_level = "skipped (blacklist)"
            db.update_task(db_path, task_id, isolation_level=isolation_level)
            log.info("[3/5] 黑名单命中，跳过沙箱 agent")

        # ---------- 4. 规则评分 + LLM 综合研判 ----------
        rules = rule_score(prefilter, tech_signals, agent_result)
        judge = Judge(create_provider_with_retry_log(cfg["llm"], db_path),
                      task_id=task_id)
        text_summary = _latest_text(db_path, task_id)
        content = judge.content_analysis(screenshots, text_summary)
        all_signals = {
            "target": {"url": url, "domain": domain},
            "static_prefilter": prefilter,
            "tech_signals": tech_signals,
            "agent": agent_result,
            "rule_score": rules,
            "content_analysis": content,
        }
        llm_result = judge.final_judge(all_signals)
        dims = merge_llm_dimensions(rules, llm_result["dimensions"])
        log.info("[4/5] 研判完成: llm_score=%s level=%s",
                 llm_result["score"], llm_result["level"])

        # ---------- 5. 报告 ----------
        report = {
            "task_id": task_id,
            "url": url,
            "domain": domain,
            "score": llm_result["score"],
            "level": llm_result["level"],
            "level_label": {"high": "高风险", "medium": "中风险",
                            "low": "低风险"}[llm_result["level"]],
            "dimensions": dims,
            "evidence": llm_result["evidence"],
            "risk_reasons": llm_result.get("risk_reasons", []),
            "confidence": llm_result["confidence"],
            "summary": llm_result["summary"],
            "screenshots": _rel_static(screenshots),
            "redirect_chain": agent_result.get("redirect_chain") or [url],
            "signals_table": prefilter.get("signals", []),
            "isolation_level": isolation_level,
            "agent_rounds": agent_result.get("rounds", 0),
            "rule_score": rules["total"],
            "llm_score": llm_result["score"],
        }
        report_path = render_report(report_dir, report)
        db.update_task(db_path, task_id, status="done",
                       rule_score=rules["total"],
                       llm_score=llm_result["score"],
                       level=llm_result["level"],
                       report_path=report_path,
                       finished_at=__import__("time").time())
        log.info("[5/5] 报告已生成: %s", report_path)
        return {"ok": True, "task_id": task_id, "report_path": report_path,
                "report": report}

    except UrlRejectedError as e:
        db.update_task(db_path, task_id, status="error",
                       error=f"预检拒绝: {e}",
                       finished_at=__import__("time").time())
        return {"ok": False, "task_id": task_id, "error": f"URL 被安全预检拒绝: {e}"}
    except Exception as e:  # noqa: BLE001
        log.exception("分析任务失败")
        db.update_task(db_path, task_id, status="error", error=str(e)[:500],
                       finished_at=__import__("time").time())
        return {"ok": False, "task_id": task_id, "error": str(e)}


def _db_blocked_result(db_path: str, cfg: dict, task_id: str, url: str,
                       domain: str, hit: dict, evidence_dir: str,
                       report_dir: str) -> dict:
    """诈骗库命中：跳过 agent 与 LLM，直接生成拦截报告（零 token 开销）。"""
    source_label = ("内置黑名单" if hit["source"] == "builtin"
                    else "用户举报（经审核确认）")
    summary = (f"该网址已被举报并经审核确认为诈骗网站（来源：{source_label}，"
               f"历史拦截 {hit['hit_count']} 次），系统直接拦截，"
               f"本次未调用大模型检测。请勿访问，如已造成损失请及时报警。")
    report = {
        "task_id": task_id,
        "url": url,
        "domain": domain,
        "score": 95,
        "level": "high",
        "level_label": "高风险",
        "dimensions": {"url": 30, "tech": 0, "content": 30, "behavior": 0},
        "evidence": [
            f"诈骗网址库命中：记录 id={hit['id']}，主域 {hit['domain']}，"
            f"入库来源 {source_label}",
            f"该记录累计拦截 {hit['hit_count']} 次",
            "按库优先策略跳过沙箱取证与大模型研判，节省 token 开销",
        ],
        "risk_reasons": [{
            "category": "可疑域名",
            "reason": f"该{ '网址' if hit.get('url') else '主域' }已在诈骗网址库中"
                      f"（{source_label}），用户举报经审核确认",
            "evidence": f"库记录 id={hit['id']}，历史拦截 {hit['hit_count']} 次",
        }],
        "confidence": 1.0,
        "summary": summary,
        "screenshots": [],
        "redirect_chain": [url],
        "signals_table": [{"name": "诈骗网址库", "hit": True,
                           "detail": f"命中记录 id={hit['id']}（{source_label}）"}],
        "isolation_level": "skipped (fraud_db)",
        "agent_rounds": 0,
        "rule_score": 95,
        "llm_score": "-",
        "blocked_by": hit["source"],
    }
    report_path = render_report(report_dir, report)
    db.update_task(db_path, task_id, status="done",
                   rule_score=95, level="high",
                   report_path=report_path,
                   finished_at=__import__("time").time())
    log.info("[5/5] 拦截报告已生成: %s", report_path)
    return {"ok": True, "task_id": task_id, "report_path": report_path,
            "report": report}


def _latest_text(db_path: str, task_id: str) -> str:
    ev = db.list_evidence(db_path, task_id)
    texts = [e["content"] for e in ev if e["kind"] == "text"]
    return texts[-1] if texts else "（无页面文本）"


def _rel_static(paths: list[str]) -> list[str]:
    """把绝对路径转成相对 static/ 的 URL 路径，供报告引用。"""
    out = []
    for p in paths:
        q = Path(p)
        for part in ("static",):
            if part in q.parts:
                out.append("/" + "/".join(q.parts[q.parts.index(part):]))
                break
        else:
            out.append(q.as_posix())
    return out
