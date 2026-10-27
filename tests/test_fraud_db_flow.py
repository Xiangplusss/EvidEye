"""举报 → 审核 → 诈骗库入库 → 数据库优先拦截 全链路测试（不依赖 LLM key）。
运行: python tests/test_fraud_db_flow.py
"""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from storage import db  # noqa: E402


def main() -> None:
    tmp = Path(tempfile.mkdtemp())
    db_path = str(tmp / "test.db")

    # 1. 举报单提交 + 人工审核通过 → 入库
    rep = db.submit_report(db_path, "https://scam.example/fake-pay",
                           "scam.example", "phishing", "仿冒支付页面")
    assert rep["status"] == "pending", rep
    rep = db.review_report(db_path, rep["id"], approve=True,
                           reviewer="manual", note="人工确认")
    assert rep["status"] == "approved"
    rows = db.list_fraud_db(db_path)
    assert len(rows) == 1 and rows[0]["domain"] == "scam.example", rows
    print("[OK] 举报 → 人工审核 → 写入诈骗库")

    # 2. 审核状态机：重复审核应报错
    try:
        db.review_report(db_path, rep["id"], approve=False)
        raise AssertionError("重复审核未被拒绝")
    except ValueError:
        print("[OK] 已审核举报单不可重复审核")

    # 3. 精确 URL 命中优先于整域记录 + hit_count 自增
    db.add_fraud_db(db_path, "https://scam.example/exact", "scam.example",
                    source="user_report")
    hit = db.fraud_db_hit(db_path, "https://scam.example/exact", "scam.example")
    assert hit and hit["url"] == "https://scam.example/exact"
    hit2 = db.fraud_db_hit(db_path, "https://scam.example/another-path",
                           "scam.example")
    assert hit2 and hit2["domain"] == "scam.example" and hit2["url"] is None, hit2
    rows = {r["id"]: r for r in db.list_fraud_db(db_path)}
    assert rows[hit["id"]]["hit_count"] == 1
    print("[OK] 诈骗库查询：URL 精确优先 / 整域兜底 / hit_count 自增")

    # 4. 未命中返回 None
    assert db.fraud_db_hit(db_path, "https://clean-site.org/", "clean-site.org") is None
    print("[OK] 未命中正常返回 None")

    # 5. 端到端：pipeline 诈骗库拦截（不调用 LLM）
    from pipeline import analyze_url, load_config
    cfg = load_config()
    cfg = {**cfg,
           "storage": {**cfg["storage"],
                       "db_path": str(tmp / "e2e.db"),
                       "evidence_dir": str(tmp / "ev"),
                       "report_dir": str(tmp / "rep")}}
    # 用真实可解析域名模拟"已入库的诈骗主域"
    db.add_fraud_db(cfg["storage"]["db_path"], None, "example.com",
                    source="user_report")
    result = analyze_url("https://example.com/fraud-page", cfg)
    assert result["ok"], result
    r = result["report"]
    assert r.get("blocked_by") == "user_report", r
    assert r["level"] == "high" and r["score"] == 95
    assert Path(result["report_path"]).exists()
    # 确认零 LLM 调用
    calls = db.cost_summary(cfg["storage"]["db_path"])
    assert not calls, f"拦截路径不应产生 LLM 调用: {calls}"
    print(f"[OK] pipeline 拦截：blocked_by=user_report，报告已生成，"
          f"零 LLM 调用 → {result['report_path']}")

    # 6. 拦截报告含"沙箱安全访问"横幅（低风险才显示，拦截不显示）
    html = Path(result["report_path"]).read_text(encoding="utf-8")
    assert "已由诈骗网址库直接拦截" in html
    print("[OK] 拦截横幅渲染正常")

    print("\n全部通过 ✔")


if __name__ == "__main__":
    main()
