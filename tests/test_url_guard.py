"""url_guard 单元测试（方案 S3 验收：内网 URL 被拒）。"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from precheck.url_guard import (  # noqa: E402
    UrlRejectedError, normalize_url, registered_domain)


@pytest.mark.parametrize("bad", [
    "http://127.0.0.1/x",
    "http://10.0.0.1/",
    "http://192.168.1.1/admin",
    "http://172.16.0.5/",
    "http://169.254.169.254/latest/meta-data",
    "http://[::1]:8080/",
    "ftp://example.com/file",
    "javascript:alert(1)",
    "file:///C:/Windows",
])
def test_inner_or_bad_scheme_rejected(bad):
    with pytest.raises(UrlRejectedError):
        normalize_url(bad)


def test_normalize_adds_scheme_and_strips_tracking():
    url = normalize_url("example.com/a?utm_source=x&id=3&fbclid=y")
    assert url == "https://example.com/a?id=3"


def test_registered_domain_extraction():
    assert registered_domain("https://a.b.example.co.uk/x") == "example.co.uk"
    assert registered_domain("https://login.taobao.com") == "taobao.com"


def test_domain_resolution_failure():
    # .invalid 是 RFC 6761 保留 TLD，保证不可解析；guard() 含 DNS 解析校验
    from precheck.url_guard import guard
    with pytest.raises(UrlRejectedError):
        guard("https://nonexistent-host.invalid")


def test_public_url_passes():
    assert normalize_url("http://example.com") == "http://example.com"
