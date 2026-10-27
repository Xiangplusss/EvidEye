"""安全预检：URL 规范化 + SSRF 防护。

规则（方案 §6.1）：
- 拒绝无 scheme、非 http(s) 协议
- 拒绝 IP 为私有/回环/链路本地（127/8, 10/8, 172.16/12, 192.168/16, 169.254/16, ::1）
- 域名解析后落入内网同样拒绝（防 DNS rebinding 简化为解析一次后校验）
- 规范化：补全 scheme、去跟踪参数、提取注册主域（tldextract）
"""
from __future__ import annotations

import ipaddress
import socket
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

import tldextract

# 需要剔除的跟踪参数
_TRACKING_PARAMS = {
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
    "spm", "scm", "pvid", "from", "fbclid", "gclid", "igshid", "mc_cid",
    "mc_eid", "ref", "referrer",
}

_SCHEME_ALLOWED = {"http", "https"}


class UrlRejectedError(ValueError):
    """URL 未通过安全预检。"""


def _ip_is_forbidden(ip: str) -> bool:
    """仅对字面量 IP 做判断；非 IP 字符串抛 ValueError 由调用方处理。"""
    addr = ipaddress.ip_address(ip)  # 非 IP 时抛 AddressValueError
    return (
        addr.is_private or addr.is_loopback or addr.is_link_local
        or addr.is_multicast or addr.is_reserved or addr.is_unspecified
    )


def normalize_url(raw: str) -> str:
    """补全 scheme、去跟踪参数。不改变目标主机。"""
    url = raw.strip()
    if not url:
        raise UrlRejectedError("URL 为空")
    if "://" not in url:
        # 先识别裸 scheme（如 javascript:alert(1)、file:C:/x），拒绝后再补全
        import re
        m = re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*:", url)
        if m:
            raise UrlRejectedError(f"仅允许 http/https 协议，收到: {m.group(0)[:-1]}")
        url = "https://" + url
    parsed = urlparse(url)
    if parsed.scheme.lower() not in _SCHEME_ALLOWED:
        raise UrlRejectedError(f"仅允许 http/https 协议，收到: {parsed.scheme}")
    if not parsed.hostname:
        raise UrlRejectedError("URL 缺少主机名")
    host = parsed.hostname
    # 立即以字面量形式检查（IP 直连 /明显内网主机名）
    try:
        if _ip_is_forbidden(host):
            raise UrlRejectedError("禁止访问内网/回环地址")
    except UrlRejectedError:
        raise
    except ValueError:
        pass  # 是域名而非 IP，交给 resolve 阶段校验    # 去跟踪参数
    if parsed.query:
        kept = [(k, v) for k, v in parse_qsl(parsed.query, keep_blank_values=True)
                if k.lower() not in _TRACKING_PARAMS]
        parsed = parsed._replace(query=urlencode(kept))
    return urlunparse(parsed)


def resolve_and_verify(url: str) -> str:
    """解析域名并校验解析结果不落入内网（DNS rebinding 简化防护）。

    返回解析出的首个公网 IP。解析失败/全部落内网则拒绝。
    """
    parsed = urlparse(url)
    host = parsed.hostname
    try:
        ipaddress.ip_address(host)
        return host  # 字面量 IP，normalize 阶段已校验
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, parsed.port or (443 if parsed.scheme == "https" else 80))
    except socket.gaierror as e:
        raise UrlRejectedError(f"域名解析失败: {host} ({e})") from e
    addrs = {info[4][0] for info in infos}
    public = [a for a in addrs if not _ip_is_forbidden(a)]
    if not public:
        raise UrlRejectedError("域名解析结果全部为内网/保留地址，已拒绝")
    return sorted(public)[0]


def registered_domain(url: str) -> str:
    """提取注册主域（xxx.co.uk -> 主域），用于信号对比与展示。"""
    parsed = urlparse(url)
    host = parsed.hostname or ""
    ext = tldextract.extract(host)
    if not ext.domain or not ext.suffix:
        return host
    return f"{ext.domain}.{ext.suffix}"


def guard(raw_url: str) -> tuple[str, str, str]:
    """完整预检流水线。

    返回 (规范化 URL, 注册主域, 解析 IP)；任何一步失败抛 UrlRejectedError。
    """
    url = normalize_url(raw_url)
    ip = resolve_and_verify(url)
    return url, registered_domain(url), ip
