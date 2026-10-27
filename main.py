"""CLI 交互入口：python main.py

交互命令（在提示符输入）：
  <网址>            检测该网址（诈骗库命中直接拦截；低风险可继续沙箱访问）
  s [网址]          在沙箱中安全访问（不落真实设备）；不带参数则访问最近低风险结果
  report <网址>     提交诈骗举报（自动预审，未达阈值转人工）
  review            人工审核待处理举报（a <序号> 通过 / r <序号> 驳回）
  db                查看诈骗网址库
  q / 直接回车      退出
"""
from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

EXIT_WORDS = {"q", "quit", "exit", "退出", "exit()"}

BANNER = """
===============================================
   诈骗网站识别 Demo（命令行交互版）
   命令:
     <网址>         检测网址（约 1-3 分钟，诈骗库命中秒级拦截）
     s [网址]       沙箱安全访问（隔离浏览器，真实设备不受危害）
     report <网址>  提交诈骗举报
     review         人工审核待处理举报
     db             查看诈骗网址库
     q              退出
==============================================="""

_ROOT = Path(__file__).parent


def _db_path(cfg: dict) -> str:
    return str(_ROOT / cfg["storage"]["db_path"])


# ---------------- 检测 ----------------

def analyze_and_print(url: str, cfg: dict) -> dict | None:
    """执行单次分析并打印结果摘要。返回 report dict（失败返回 None）。"""
    from pipeline import analyze_url

    result = analyze_url(url, cfg)
    if not result["ok"]:
        print(f"\n[失败] {result['error']}", file=sys.stderr)
        return None

    rep = result["report"]
    print("\n──────────── 检测结果 ────────────")
    print(f"任务 ID   : {result['task_id']}")
    print(f"目标网址  : {rep['url']}")

    if rep.get("blocked_by"):
        print("处理方式  : ⛔ 诈骗网址库直接拦截（未调用大模型）")
        print(f"风险评分  : {rep['score']}/100（{rep['level_label']}）")
        print(f"AI 结论   : {rep['summary']}")
        print("──────────────────────────────────")
        return rep

    print(f"风险评分  : {rep['score']}/100（{rep['level_label']}，置信度 "
          f"{rep['confidence'] * 100:.0f}%）")
    dims = rep["dimensions"]
    print(f"维度得分  : URL特征 {dims['url']}/30 | 技术特征 {dims['tech']}/25"
          f" | 内容特征 {dims['content']}/30 | 交互特征 {dims['behavior']}/15")

    if rep.get("risk_reasons"):
        print("\n不可信原因分析:")
        for i, r in enumerate(rep["risk_reasons"], 1):
            print(f"  {i}. [{r['category']}] {r['reason']}")
            print(f"     证据: {r['evidence']}")

    if rep.get("screenshots"):
        print(f"\n页面截图  : {len(rep['screenshots'])} 张（已嵌入报告）")
    print(f"检测报告  : {result['report_path']}")
    print(f"AI 结论   : {rep['summary']}")
    if rep["level"] == "low":
        print("提示      : 判定为低风险，输入 s 可在沙箱中安全访问该网址")
    print("──────────────────────────────────")
    return rep


# ---------------- 沙箱安全访问 ----------------

def safe_browse(url: str, cfg: dict) -> None:
    """交互式沙箱浏览：导航/点链接/后退，截图落盘供查看。"""
    from sandbox.browse_session import SafeBrowseSession

    evidence_dir = str(_ROOT / cfg["storage"]["evidence_dir"])
    print(f"\n启动沙箱安全访问（隔离浏览器，真实设备不接触目标站点）…")
    session = SafeBrowseSession(cfg, evidence_dir, session_id="cli")
    try:
        session.start()
        st = session.goto(url)
        print(f"[沙箱] 已打开: {st['url']}  《{st['title']}》"
              f"（隔离级别 {session.sb.isolation}）")
        _print_links(session)

        while True:
            try:
                cmd = input("\n[沙箱] 序号=打开对应链接 | u <网址>=导航 | "
                            "b=后退 | r=刷新截图 | q=退出> ").strip()
            except (EOFError, KeyboardInterrupt):
                break
            if not cmd or cmd.lower() in EXIT_WORDS:
                break
            if cmd == "b":
                st = session.back()
                print(f"[沙箱] 后退 → {st['url']}")
                _print_links(session)
            elif cmd == "r":
                pass
            elif cmd.startswith("u "):
                try:
                    st = session.goto(cmd[2:].strip())
                    print(f"[沙箱] 已打开: {st['url']}")
                    _print_links(session)
                except Exception as e:  # noqa: BLE001
                    print(f"[沙箱] 导航被拒绝: {e}")
            elif cmd.isdigit():
                links = session.state()["links"]
                idx = int(cmd) - 1
                if 0 <= idx < len(links):
                    try:
                        st = session.goto(links[idx]["href"])
                        print(f"[沙箱] 已打开: {st['url']}")
                        _print_links(session)
                    except Exception as e:  # noqa: BLE001
                        print(f"[沙箱] 导航失败: {e}")
                else:
                    print(f"[沙箱] 无此序号（1-{len(links)}）")
            else:
                print("[沙箱] 未知命令")

            p = session.shot_path()
            print(f"[沙箱] 当前页面截图: {p}")
    except Exception as e:  # noqa: BLE001
        print(f"[沙箱] 会话异常: {e}", file=sys.stderr)
    finally:
        session.close()
        print("[沙箱] 会话已结束，隔离环境已销毁")


def _print_links(session) -> None:
    links = session.state()["links"]
    if links:
        print(f"\n页面链接（前 {len(links)} 条）:")
        for i, l in enumerate(links, 1):
            print(f"  {i:>2}. {l['text']}  ←  {l['href'][:70]}")
    else:
        print("\n（页面无外链）")


# ---------------- 举报与审核 ----------------

def submit_report_flow(url: str, cfg: dict) -> None:
    """举报提交流程：输入类型/描述 → 自动预审 → 显示处理结果。"""
    from analyze.review import auto_review
    from storage import db

    try:
        from precheck.url_guard import guard
        norm_url, domain, _ = guard(url)
    except Exception as e:  # noqa: BLE001
        print(f"[举报] URL 预检失败（仍可提交，按原文处理）: {e}")
        norm_url, domain = url.strip(), url.strip()

    print("\n举报类型: 1=钓鱼仿冒 2=虚假投资理财 3=赌博 4=色情违法 回车=其他")
    rmap = {"1": "phishing", "2": "investment", "3": "gambling", "4": "porn"}
    try:
        choice = input("选择类型: ").strip()
    except (EOFError, KeyboardInterrupt):
        return
    try:
        desc = input("补充描述（可回车）: ").strip()
    except (EOFError, KeyboardInterrupt):
        desc = ""

    db_path = _db_path(cfg)
    rep = db.submit_report(db_path, norm_url, domain,
                           rmap.get(choice, "other"), desc)
    rep = auto_review(db_path, cfg, rep["id"])
    if rep["status"] == "approved":
        print(f"[举报] #{rep['id']} 已自动审核通过并写入诈骗网址库，"
              f"后续检测将直接拦截该网址")
    else:
        print(f"[举报] #{rep['id']} 已提交，静态预审未达自动确认阈值，"
              f"转人工审核（CLI 输入 review / Web 访问 /review 页面处理）")


def review_flow(cfg: dict) -> None:
    """人工审核：列出待处理举报，按序号通过/驳回。"""
    from analyze.review import manual_review
    from storage import db

    db_path = _db_path(cfg)
    while True:
        pending = db.list_reports(db_path, status="pending")
        if not pending:
            print("[审核] 当前无待人工审核的举报单")
            return
        print(f"\n待审核举报（{len(pending)} 条）:")
        for i, r in enumerate(pending, 1):
            print(f"  {i:>2}. #{r['id']} [{r['reason']}] {r['url']}")
            if r["description"]:
                print(f"      描述: {r['description'][:80]}")
        try:
            cmd = input("a <序号>=确认诈骗入库 | r <序号>=驳回 | q=返回> ").strip()
        except (EOFError, KeyboardInterrupt):
            return
        if not cmd or cmd.lower() in EXIT_WORDS:
            return
        parts = cmd.split()
        if len(parts) == 2 and parts[0] in ("a", "r") and parts[1].isdigit():
            idx = int(parts[1]) - 1
            if 0 <= idx < len(pending):
                rid = pending[idx]["id"]
                result = manual_review(db_path, rid,
                                       approve=(parts[0] == "a"))
                print(f"[审核] #{rid} → {result['status']}"
                      + ("（已写入诈骗网址库）" if parts[0] == "a" else ""))
            else:
                print("[审核] 无此序号")
        else:
            print("[审核] 输入格式: a 1 / r 1 / q")


def show_fraud_db(cfg: dict) -> None:
    from storage import db

    rows = db.list_fraud_db(_db_path(cfg))
    if not rows:
        print("[诈骗库] 当前为空（内置黑名单在 data/blacklist.txt）")
        return
    print(f"\n诈骗网址库（{len(rows)} 条，按拦截次数排序）:")
    print(f"  {'ID':>4}  {'主域':<28} {'来源':<12} {'拦截':>4}  URL")
    for r in rows:
        src = "内置" if r["source"] == "builtin" else "用户举报"
        print(f"  {r['id']:>4}  {r['domain']:<28} {src:<12} "
              f"{r['hit_count']:>4}  {(r['url'] or '(整域拦截)')[:50]}")


# ---------------- 主循环 ----------------

def main() -> int:
    parser = argparse.ArgumentParser(
        description="诈骗网站识别 demo（交互式 CLI）")
    parser.add_argument("url", nargs="?", default=None,
                        help="可选：直接传入网址则跳过交互输入")
    parser.add_argument("--config", default=None, help="配置文件路径")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s")

    from pipeline import load_config
    cfg = load_config(args.config)

    if args.url:  # 兼容旧用法：带参数直接分析
        return 0 if analyze_and_print(args.url, cfg) else 1

    print(BANNER)
    last_low_url: str | None = None
    while True:
        try:
            cmd = input("\n请输入命令或网址: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n已退出")
            return 0
        if not cmd or cmd.lower() in EXIT_WORDS:
            print("已退出")
            return 0

        low = cmd.lower()
        if low == "s" or low.startswith("s "):
            url = cmd[2:].strip() or last_low_url
            if not url:
                print("请提供网址: s <网址>（或先检测一个低风险网址）")
            else:
                safe_browse(url, cfg)
        elif low.startswith("report "):
            submit_report_flow(cmd[7:].strip(), cfg)
        elif low == "review":
            review_flow(cfg)
        elif low == "db":
            show_fraud_db(cfg)
        else:
            rep = analyze_and_print(cmd, cfg)
            if rep and rep.get("level") == "low" and not rep.get("blocked_by"):
                last_low_url = rep["url"]


if __name__ == "__main__":
    sys.exit(main())
