"""HTML 报告渲染（Jinja2）。"""
from __future__ import annotations

from datetime import datetime
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

_LEVEL_LABEL = {"high": "高风险", "medium": "中风险", "low": "低风险"}
_LEVEL_COLOR = {"high": "#c0392b", "medium": "#e67e22", "low": "#27ae60"}
_DIM_LABELS = [("url", "URL 特征", 30), ("tech", "技术特征", 25),
               ("content", "内容特征", 30), ("behavior", "交互特征", 15)]


def render_report(out_dir: str, report: dict) -> str:
    """渲染报告 HTML，返回文件绝对路径。

    report 键: task_id, url, domain, score, level, dimensions, evidence,
               confidence, summary, screenshots(相对路径列表),
               redirect_chain, signals_table, isolation_level,
               agent_rounds, rule_score, llm_score
    """
    env = Environment(loader=FileSystemLoader(
        str(Path(__file__).parent.parent / "templates")), autoescape=True)
    tpl = env.get_template("report.html.j2")
    level = report.get("level", "medium")
    dims = report.get("dimensions", {})
    html = tpl.render(
        task_id=report.get("task_id", ""),
        url=report.get("url", ""),
        domain=report.get("domain", ""),
        score=report.get("score", 0),
        level=level,
        level_label=_LEVEL_LABEL[level],
        score_color=_LEVEL_COLOR[level],
        confidence=report.get("confidence", 0),
        dims=[(k, label, dims.get(k, 0), cap) for k, label, cap in _DIM_LABELS],
        evidence=report.get("evidence", []),
        risk_reasons=report.get("risk_reasons", []),
        screenshots=report.get("screenshots", []),
        redirect_chain=report.get("redirect_chain", []),
        signals_table=report.get("signals_table", []),
        isolation_level=report.get("isolation_level", "L2"),
        agent_rounds=report.get("agent_rounds", 0),
        rule_score=report.get("rule_score", 0),
        llm_score=report.get("llm_score", 0),
        summary=report.get("summary", ""),
        blocked_by=report.get("blocked_by"),
        generated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    )
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    path = out / f"report-{report.get('task_id', 'unknown')}.html"
    path.write_text(html, encoding="utf-8")
    return str(path)
