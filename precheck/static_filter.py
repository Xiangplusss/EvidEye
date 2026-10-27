"""静态预筛模块（不依赖 LLM）。

- URL 特征规则评分（0-30 分部分信号）
- whois 域名年龄
- 内置黑名单：命中则一票判定 100 分并跳过 agent
输出：初筛信号 JSON
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path

from precheck.url_guard import registered_domain

# 品牌词（被冒充高发对象）
_BRAND_WORDS = ["taobao", "alipay", "jd", "qq", "weixin", "wechat", "icbc",
                "cmbchina", "bank", "apple", "icloud", "paypal", "amazon",
                "douyin", "meituan", "pinduoduo", "ctrip", "12306"]
# 敏感关键词
_SENSITIVE_WORDS = ["login", "signin", "verify", "secure", "account",
                    "update", "pay", "charge", "recharge", "wallet",
                    " withdrawal", "verifycode", "auth"]
# 可疑 TLD（历史钓鱼高发，样例集）
_SUSPECT_TLDS = {"top", "xyz", "tk", "gq", "cf", "ml", "click", "country",
                 "work", "loan", "icu", "cyou", "monster"}
_PUNYCODE_RE = re.compile(r"^xn--", re.IGNORECASE)
_IP_HOST_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def load_blacklist(path: str) -> set[str]:
    p = Path(path)
    if not p.exists():
        return set()
    return {line.strip().lower() for line in p.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.startswith("#")}


def whois_age_days(domain: str) -> int | None:
    """域名注册天数；查询失败返回 None（不中断流程）。"""
    try:
        import whois  # python-whois
        w = whois.whois(domain)
        created = w.creation_date
        if isinstance(created, list):
            created = created[0]
        if not created:
            return None
        if isinstance(created, str):
            for fmt in ("%Y-%m-%d", "%Y-%m-%dT%H:%M:%S", "%d-%b-%Y"):
                try:
                    created = datetime.strptime(created[:19], fmt)
                    break
                except ValueError:
                    continue
            else:
                return None
        return (datetime.now(timezone.utc) - created.replace(tzinfo=timezone.utc)).days
    except Exception:  # noqa: BLE001
        return None


def url_signals(url: str, domain: str) -> list[dict]:
    """URL 特征信号，每条 {"name", "hit", "detail", "weight"}。"""
    signals = []

    def add(name: str, hit: bool, detail: str, weight: int = 0):
        signals.append({"name": name, "hit": hit, "detail": detail,
                        "weight": weight})

    host = url.split("//", 1)[-1].split("/", 1)[0].split(":")[0].lower()

    if _IP_HOST_RE.match(host):
        add("ip_direct", True, "URL 使用 IP 直连而非域名", 10)
    brand_hit = [b for b in _BRAND_WORDS if b in host]
    if brand_hit and not host.endswith(("com", "cn", "net")):
        add("brand_in_host", True,
            f"主机名含品牌词 {brand_hit} 但非对应官方域名", 10)
    elif brand_hit:
        add("brand_in_host", True, f"主机名含品牌词 {brand_hit}，需比对域名", 4)
    sens_hit = [s.strip() for s in _SENSITIVE_WORDS if s.strip() in host]
    if sens_hit:
        add("sensitive_keyword", True, f"主机名含敏感关键词 {sens_hit}", 5)
    labels = host.split(".")
    if len(labels) >= 5:
        add("deep_subdomain", True,
            f"子域名层级过深({len(labels)} 级)，常见伪装手法", 6)
    tld = labels[-1]
    if tld in _SUSPECT_TLDS:
        add("suspect_tld", True, f"可疑顶级域名 .{tld}", 8)
    if any(_PUNYCODE_RE.match(lb) for lb in labels):
        add("punycode", True, "域名含 Punycode(xn--) 编码，可能仿冒字形", 10)
    if url.startswith("http://"):
        add("no_https", True, "URL 为 HTTP 明文", 5)
    return signals


def static_prefilter(url: str, domain: str, cfg: dict) -> dict:
    """静态预筛主入口。返回初筛信号 JSON。

    blacklist_hit=True 时 risk_score=100，调用方应跳过 agent 直接研判。
    """
    blacklist = load_blacklist(cfg.get("blacklist_file", "data/blacklist.txt"))
    hit = domain.lower() in blacklist or url.lower() in blacklist

    signals = url_signals(url, domain)
    age = None
    if not hit:
        age = whois_age_days(domain)
        if age is not None and age < cfg.get("whois_fresh_days", 30):
            signals.append({"name": "fresh_domain", "hit": True,
                            "detail": f"域名注册仅 {age} 天", "weight": 10})
        elif age is not None:
            signals.append({"name": "fresh_domain", "hit": False,
                            "detail": f"域名注册 {age} 天", "weight": 0})
        else:
            signals.append({"name": "fresh_domain", "hit": False,
                            "detail": "whois 查询失败，无法确认域名年龄",
                            "weight": 0})

    url_score = min(30, sum(s["weight"] for s in signals if s["hit"]))
    return {
        "blacklist_hit": hit,
        "risk_score": 100 if hit else url_score,
        "url_score": url_score,
        "domain": domain,
        "whois_age_days": age,
        "signals": signals,
    }


def dump(prefilter_result: dict) -> str:
    return json.dumps(prefilter_result, ensure_ascii=False, indent=2)
