"""SQLite 存储层：分析任务、证据、LLM 调用日志。"""
from __future__ import annotations

import json
import sqlite3
import threading
import time
import uuid
from pathlib import Path

_local = threading.local()

_SCHEMA = """
CREATE TABLE IF NOT EXISTS tasks (
    id TEXT PRIMARY KEY,
    url TEXT NOT NULL,
    domain TEXT,
    status TEXT NOT NULL DEFAULT 'pending',   -- pending/running/done/error
    isolation_level TEXT,                      -- L1/L2
    rule_score INTEGER,
    llm_score INTEGER,
    level TEXT,                                -- high/medium/low
    report_path TEXT,
    error TEXT,
    created_at REAL NOT NULL,
    finished_at REAL
);

CREATE TABLE IF NOT EXISTS evidence (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id TEXT NOT NULL REFERENCES tasks(id),
    kind TEXT NOT NULL,          -- screenshot/text/form/redirect/whois/tool_result
    label TEXT,
    content TEXT,                -- 文本类内容或文件相对路径
    created_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS llm_calls (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id TEXT,
    provider TEXT,
    model TEXT,
    purpose TEXT,                -- agent/judge/vision
    prompt_chars INTEGER,
    completion_tokens INTEGER,
    prompt_tokens INTEGER,
    duration_ms INTEGER,
    ok INTEGER NOT NULL,
    error TEXT,
    created_at REAL NOT NULL
);

-- 用户举报单（状态机: pending → approved / rejected）
CREATE TABLE IF NOT EXISTS reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT NOT NULL,
    domain TEXT NOT NULL,
    reason TEXT,                 -- 举报类型: phishing/investment/gambling/porn/other
    description TEXT,
    task_id TEXT,                -- 关联检测任务（可选）
    status TEXT NOT NULL DEFAULT 'pending',
    reviewed_by TEXT,            -- auto / manual
    review_note TEXT,
    reviewed_at REAL,
    created_at REAL NOT NULL
);

-- 已确认诈骗网址库（拦截优先查询源；命中即拦截，不调用 LLM）
CREATE TABLE IF NOT EXISTS fraud_db (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT,                    -- 精确 URL（可空 = 仅按主域拦截）
    domain TEXT NOT NULL,
    source TEXT NOT NULL DEFAULT 'user_report',   -- builtin / user_report
    report_id INTEGER,           -- 来源举报单
    level TEXT NOT NULL DEFAULT 'high',
    hit_count INTEGER NOT NULL DEFAULT 0,         -- 拦截次数
    created_at REAL NOT NULL,
    UNIQUE(domain, url)
);
"""


def get_conn(db_path: str) -> sqlite3.Connection:
    """每线程一个连接（SQLite 限制跨线程复用）。"""
    conn = getattr(_local, "conn", None)
    if conn is None:
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.executescript(_SCHEMA)
        _local.conn = conn
    return conn


def new_task_id() -> str:
    return uuid.uuid4().hex[:12]


def create_task(db_path: str, url: str, domain: str) -> str:
    task_id = new_task_id()
    get_conn(db_path).execute(
        "INSERT INTO tasks (id, url, domain, status, created_at) VALUES (?,?,?,?,?)",
        (task_id, url, domain, "pending", time.time()),
    )
    get_conn(db_path).commit()
    return task_id


def update_task(db_path: str, task_id: str, **fields) -> None:
    allowed = {"status", "isolation_level", "rule_score", "llm_score",
               "level", "report_path", "error", "finished_at"}
    keys = [k for k in fields if k in allowed]
    if not keys:
        return
    sets = ", ".join(f"{k}=?" for k in keys)
    get_conn(db_path).execute(
        f"UPDATE tasks SET {sets} WHERE id=?",
        [fields[k] for k in keys] + [task_id],
    )
    get_conn(db_path).commit()


def add_evidence(db_path: str, task_id: str, kind: str, label: str,
                 content: str) -> None:
    get_conn(db_path).execute(
        "INSERT INTO evidence (task_id, kind, label, content, created_at) "
        "VALUES (?,?,?,?,?)",
        (task_id, kind, label, content, time.time()),
    )
    get_conn(db_path).commit()


def list_evidence(db_path: str, task_id: str) -> list[dict]:
    rows = get_conn(db_path).execute(
        "SELECT kind, label, content, created_at FROM evidence "
        "WHERE task_id=? ORDER BY id", (task_id,)
    ).fetchall()
    return [dict(r) for r in rows]


def log_llm_call(db_path: str, task_id: str | None, provider: str, model: str,
                 purpose: str, prompt_chars: int, usage: dict | None,
                 duration_ms: int, ok: bool, error: str | None) -> None:
    """只落 token 用量统计，不落页面内容（§8.2 安全约束 4）。"""
    usage = usage or {}
    get_conn(db_path).execute(
        "INSERT INTO llm_calls (task_id, provider, model, purpose, prompt_chars,"
        " completion_tokens, prompt_tokens, duration_ms, ok, error, created_at)"
        " VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        (task_id, provider, model, purpose, prompt_chars,
         usage.get("completion_tokens"), usage.get("prompt_tokens"),
         duration_ms, 1 if ok else 0, error, time.time()),
    )
    get_conn(db_path).commit()


def get_task(db_path: str, task_id: str) -> dict | None:
    row = get_conn(db_path).execute(
        "SELECT * FROM tasks WHERE id=?", (task_id,)
    ).fetchone()
    return dict(row) if row else None


def cost_summary(db_path: str) -> dict:
    """LLM 成本统计（token 级）。"""
    rows = get_conn(db_path).execute(
        "SELECT purpose, COUNT(*) n, SUM(prompt_tokens) pt, "
        "SUM(completion_tokens) ct, AVG(duration_ms) avg_ms "
        "FROM llm_calls WHERE ok=1 GROUP BY purpose"
    ).fetchall()
    return {r["purpose"]: {"calls": r["n"], "prompt_tokens": r["pt"] or 0,
                           "completion_tokens": r["ct"] or 0,
                           "avg_ms": round(r["avg_ms"] or 0)}
            for r in rows}


# ==================== 用户举报 + 诈骗网址库 ====================

REPORT_REASONS = {
    "phishing": "钓鱼仿冒",
    "investment": "虚假投资理财",
    "gambling": "赌博",
    "porn": "色情违法",
    "other": "其他诈骗",
}


def submit_report(db_path: str, url: str, domain: str, reason: str,
                  description: str, task_id: str | None = None) -> dict:
    """提交举报单（初始 pending）。返回举报单 dict。"""
    reason = reason if reason in REPORT_REASONS else "other"
    cur = get_conn(db_path).execute(
        "INSERT INTO reports (url, domain, reason, description, task_id,"
        " status, created_at) VALUES (?,?,?,?,?,'pending',?)",
        (url, domain, reason, (description or "")[:1000], task_id, time.time()),
    )
    get_conn(db_path).commit()
    return get_report(db_path, cur.lastrowid)


def get_report(db_path: str, report_id: int) -> dict | None:
    row = get_conn(db_path).execute(
        "SELECT * FROM reports WHERE id=?", (report_id,)).fetchone()
    return dict(row) if row else None


def list_reports(db_path: str, status: str | None = None,
                 limit: int = 100) -> list[dict]:
    if status:
        rows = get_conn(db_path).execute(
            "SELECT * FROM reports WHERE status=? ORDER BY id DESC LIMIT ?",
            (status, limit)).fetchall()
    else:
        rows = get_conn(db_path).execute(
            "SELECT * FROM reports ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
    return [dict(r) for r in rows]


def review_report(db_path: str, report_id: int, approve: bool,
                  reviewer: str = "manual", note: str | None = None) -> dict:
    """审核举报单。通过则写入诈骗网址库（domain 级拦截）。"""
    rep = get_report(db_path, report_id)
    if not rep:
        raise ValueError(f"举报单 {report_id} 不存在")
    if rep["status"] != "pending":
        raise ValueError(f"举报单 {report_id} 已审核（{rep['status']}）")
    status = "approved" if approve else "rejected"
    get_conn(db_path).execute(
        "UPDATE reports SET status=?, reviewed_by=?, review_note=?,"
        " reviewed_at=? WHERE id=?",
        (status, reviewer, note or "", time.time(), report_id),
    )
    get_conn(db_path).commit()
    if approve:
        # 举报确认按整域拦截（诈骗站路径多变，域级更稳健）
        add_fraud_db(db_path, None, rep["domain"],
                     source="user_report", report_id=report_id)
    return get_report(db_path, report_id)


def add_fraud_db(db_path: str, url: str | None, domain: str,
                 source: str = "user_report", report_id: int | None = None,
                 level: str = "high") -> None:
    """写入/更新诈骗库（同 domain+url 幂等）。url=None 表示整域拦截。"""
    get_conn(db_path).execute(
        "INSERT INTO fraud_db (url, domain, source, report_id, level,"
        " hit_count, created_at) VALUES (?,?,?,?,?,0,?)"
        " ON CONFLICT(domain, url) DO NOTHING",
        (url, domain, source, report_id, level, time.time()),
    )
    get_conn(db_path).commit()


def fraud_db_hit(db_path: str, url: str, domain: str) -> dict | None:
    """拦截优先查询：精确 URL 命中优先，其次整域命中。

    命中时自增 hit_count 并返回该条记录；未命中返回 None。
    """
    conn = get_conn(db_path)
    row = conn.execute(
        "SELECT * FROM fraud_db WHERE url=? LIMIT 1", (url,)).fetchone()
    if not row:
        row = conn.execute(
            "SELECT * FROM fraud_db WHERE domain=? AND url IS NULL LIMIT 1",
            (domain,)).fetchone()
    if not row:
        return None
    conn.execute("UPDATE fraud_db SET hit_count=hit_count+1 WHERE id=?",
                 (row["id"],))
    conn.commit()
    return dict(conn.execute("SELECT * FROM fraud_db WHERE id=?",
                             (row["id"],)).fetchone())


def list_fraud_db(db_path: str, limit: int = 200) -> list[dict]:
    rows = get_conn(db_path).execute(
        "SELECT * FROM fraud_db ORDER BY hit_count DESC, id DESC LIMIT ?",
        (limit,)).fetchall()
    return [dict(r) for r in rows]
