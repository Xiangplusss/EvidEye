"""低风险网址的沙箱安全访问会话。

判定为低风险的网址允许用户继续访问，但访问发生在隔离浏览器中
（L1 Docker 容器 / L2 受限配置），真实设备不接触目标站点：
- 所有导航、点击、后退都发生在沙箱 page 上；
- 页面以截图形式回传给用户（CLI 打印路径 / Web 轮询刷新）；
- 禁下载/禁通知/禁定位沿用 SandboxBrowser 通用约束；
- 会话结束即销毁容器 / 临时 profile。
"""
from __future__ import annotations

import logging
import time

from precheck.url_guard import guard
from sandbox.browser import SandboxBrowser

log = logging.getLogger(__name__)

_LINKS_JS = """
() => {
  const seen = new Set();
  const out = [];
  for (const a of document.querySelectorAll('a[href]')) {
    const href = a.href || '';
    if (!href.startsWith('http')) continue;
    if (seen.has(href)) continue;
    seen.add(href);
    const text = (a.innerText || a.textContent || '').trim()
      .replace(/\\s+/g, ' ').slice(0, 40);
    out.push({ text: text || href.slice(0, 40), href });
    if (out.length >= 25) break;
  }
  return out;
}
"""


class SafeBrowseSession:
    """一次沙箱浏览会话。close() 前请确保调用过 start()。"""

    def __init__(self, cfg: dict, evidence_dir: str, session_id: str):
        self.cfg = cfg
        self.session_id = session_id
        self.sb = SandboxBrowser(cfg, evidence_dir)
        self.created_at = time.time()
        self._shot_seq = 0

    # ---------- lifecycle ----------
    def start(self) -> None:
        self.sb.start()

    def close(self) -> None:
        try:
            self.sb.stop()
        except Exception:  # noqa: BLE001
            log.exception("安全浏览会话关闭异常")

    # ---------- actions ----------
    def goto(self, raw_url: str) -> dict:
        """导航到目标 URL（复用 url_guard 的 SSRF 防护）。"""
        url, _domain, _ip = guard(raw_url)
        resp = self.sb.page.goto(url, wait_until="domcontentloaded")
        self.sb.record_redirect(self.sb.page.url)
        return {"ok": True, "status": resp.status if resp else None,
                "url": self.sb.page.url,
                "title": self._safe_title()}

    def click(self, x_ratio: float, y_ratio: float) -> dict:
        """按视口比例坐标点击（Web 端点选导航用）。"""
        vp = self.sb.page.viewport_size
        self.sb.page.mouse.click(int(vp["width"] * x_ratio),
                                 int(vp["height"] * y_ratio))
        self.sb.page.wait_for_timeout(1500)
        self.sb.record_redirect(self.sb.page.url)
        return {"ok": True, "url": self.sb.page.url,
                "title": self._safe_title()}

    def back(self) -> dict:
        self.sb.page.go_back(wait_until="domcontentloaded")
        return {"ok": True, "url": self.sb.page.url,
                "title": self._safe_title()}

    def refresh(self) -> dict:
        self.sb.page.reload(wait_until="domcontentloaded")
        return {"ok": True, "url": self.sb.page.url,
                "title": self._safe_title()}

    # ---------- state / evidence ----------
    def state(self) -> dict:
        return {"session_id": self.session_id, "url": self.sb.page.url,
                "title": self._safe_title(), "isolation": self.sb.isolation,
                "redirect_chain": self.sb.redirect_chain,
                "links": self._links()}

    def shot_path(self, full_page: bool = False) -> str:
        """截取当前页面到证据目录并返回路径（自增序号防覆盖）。"""
        self._shot_seq += 1
        path = (self.sb.evidence_dir /
                f"safe-{self.session_id}-{self._shot_seq:03d}.png")
        self.sb.page.screenshot(path=str(path), full_page=full_page)
        return str(path)

    # ---------- internals ----------
    def _safe_title(self) -> str:
        try:
            return self.sb.page.title()
        except Exception:  # noqa: BLE001
            return ""

    def _links(self) -> list[dict]:
        try:
            return self.sb.page.evaluate(_LINKS_JS)
        except Exception:  # noqa: BLE001
            return []
