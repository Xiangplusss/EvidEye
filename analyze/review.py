"""举报审核：自动审核（规则）+ 人工审核入口。

流程：
  用户提交举报 → 自动预审（静态预筛规则，不耗 token）
    ├─ 黑名单命中 / 风险分 ≥ 阈值 → 自动通过，直接写入诈骗库
    └─ 未达阈值 → pending，等待人工审核（CLI `review` 命令 / Web 审核页）
  审核通过 → fraud_db 入库，后续检测优先拦截
"""
from __future__ import annotations

import logging

from storage import db

log = logging.getLogger(__name__)


def auto_review(db_path: str, cfg: dict, report_id: int) -> dict:
    """对刚提交的举报单做规则预审。返回举报单最新状态。"""
    rep = db.get_report(db_path, report_id)
    if not rep:
        raise ValueError(f"举报单 {report_id} 不存在")

    threshold = int(cfg.get("moderation", {}).get("auto_approve_score", 40))
    # 延迟导入避免循环依赖
    from precheck.static_filter import static_prefilter
    pf = static_prefilter(rep["url"], rep["domain"], cfg.get("precheck", {}))

    if pf.get("blacklist_hit") or pf.get("risk_score", 0) >= threshold:
        db.review_report(db_path, report_id, approve=True, reviewer="auto",
                         note=f"自动审核：静态预筛风险分 "
                              f"{pf.get('risk_score')}，黑名单命中 "
                              f"{pf.get('blacklist_hit')}，达到自动确认阈值")
        log.info("举报单 %s 自动审核通过（风险分 %s）",
                 report_id, pf.get("risk_score"))
    else:
        log.info("举报单 %s 转人工审核（风险分 %s < %s）",
                 report_id, pf.get("risk_score"), threshold)
    return db.get_report(db_path, report_id)


def manual_review(db_path: str, report_id: int, approve: bool,
                  note: str | None = None) -> dict:
    """人工审核入口。通过则写入诈骗库。"""
    result = db.review_report(db_path, report_id, approve=approve,
                              reviewer="manual", note=note)
    log.info("举报单 %s 人工审核：%s", report_id,
             "通过（已入库）" if approve else "驳回")
    return result
