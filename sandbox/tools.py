"""Agent 工具集定义与实现（方案 §6.2）。

每个工具以 OpenAI function 格式声明（TOOLS），实现返回 JSON 字符串。

安全边界（强制，不依赖模型自觉）：
- fill_form_test 只填充、绝不提交，假数据固定；
- submit_intercepted 必须先注册网络层 route 拦截（请求不出网），
  拦截失败立即中止并告警，返回中带 intercepted: true 供证据链核实。
"""
from __future__ import annotations

import json
import logging
import time
import uuid
from pathlib import Path

log = logging.getLogger(__name__)

# §8.2 通用约束 2：假数据固定
FAKE_DATA = {
    "text": "测试员",
    "email": "test_agent_001@example.com",
    "tel": "13800000000",
    "password": "TestAgent#001",
    "number": "13800000000",
    "search": "test",
}

# 验证码类字段名（只填占位、绝不猜测真实验证码）
_CODE_FIELD_RE_KEYWORDS = ("captcha", "code", "verify", "sms", "otp", "yzm")

# OpenAI function 格式声明
TOOLS = [
    {"type": "function", "function": {
        "name": "navigate",
        "description": "打开或跳转到指定 URL（仅限目标站点域名及其静态资源域名）",
        "parameters": {"type": "object", "properties": {
            "url": {"type": "string", "description": "要访问的 URL"}},
            "required": ["url"]}}},
    {"type": "function", "function": {
        "name": "get_page_text",
        "description": "抓取当前页面可见文本（标题+正文摘要，用于判断页面主题与话术）",
        "parameters": {"type": "object", "properties": {}}}},
    {"type": "function", "function": {
        "name": "get_forms",
        "description": "枚举当前页面所有表单：字段列表(标注密码/验证码字段)、action、method、action 与页面域名是否一致",
        "parameters": {"type": "object", "properties": {}}}},
    {"type": "function", "function": {
        "name": "fill_form_test",
        "description": "向指定表单填入固定假数据（绝不提交），观察填充结果与 3 秒内页面弹窗/提示",
        "parameters": {"type": "object", "properties": {
            "form_index": {"type": "integer", "description": "表单序号，从 0 开始"}},
            "required": ["form_index"]}}},
    {"type": "function", "function": {
        "name": "submit_intercepted",
        "description": "拦截式提交探测：先在网络层拦截所有出站请求，再真实点击 submit，数据不离开沙箱。返回前端校验反馈与提交意图",
        "parameters": {"type": "object", "properties": {
            "form_index": {"type": "integer", "description": "表单序号，从 0 开始"}},
            "required": ["form_index"]}}},
    {"type": "function", "function": {
        "name": "get_external_resources",
        "description": "列出页面引用的第三方资源域名（script/img/form action）",
        "parameters": {"type": "object", "properties": {}}}},
    {"type": "function", "function": {
        "name": "screenshot",
        "description": "对当前页面整页截图，保存为证据",
        "parameters": {"type": "object", "properties": {}}}},
    {"type": "function", "function": {
        "name": "check_whois",
        "description": "查询当前站点域名的 whois 注册信息（注册时间、注册商）",
        "parameters": {"type": "object", "properties": {}}}},
    {"type": "function", "function": {
        "name": "finish",
        "description": "结束探测并提交信号汇总（必须最后调用，summary 为你的发现总结）",
        "parameters": {"type": "object", "properties": {
            "summary": {"type": "string", "description": "对页面风险信号的总结"}},
            "required": ["summary"]}}},
]


class ToolBox:
    """工具实现集合，绑定一个 SandboxBrowser 实例。"""

    def __init__(self, browser, db_path: str, task_id: str,
                 page_text_max: int = 3000):
        self.browser = browser          # SandboxBrowser
        self.db_path = db_path
        self.task_id = task_id
        self.page_text_max = page_text_max
        self.target_domain = ""         # 由主流程在 navigate 后回填
        self.static_domains: set[str] = set()
        self.signals: dict = {}         # agent 阶段累积的信号
        self.finished = False

    # ---------- helpers ----------
    def _from_storage(self, kind: str, label: str, content: str) -> None:
        from storage import db
        db.add_evidence(self.db_path, self.task_id, kind, label, content)

    def _is_code_field(self, name: str, ftype: str, placeholder: str) -> bool:
        blob = f"{name} {placeholder}".lower()
        return any(k in blob for k in _CODE_FIELD_RE_KEYWORDS)

    # ---------- tools ----------
    def navigate(self, url: str) -> str:
        from precheck.url_guard import normalize_url, resolve_and_verify, registered_domain
        try:
            url = normalize_url(url)
            resolve_and_verify(url)  # 导航前校验（§8.2 约束 1）
        except ValueError as e:
            return json.dumps({"ok": False, "error": f"URL 被安全预检拒绝: {e}"},
                              ensure_ascii=False)
        page = self.browser.page
        resp = page.goto(url, wait_until="domcontentloaded")
        page.wait_for_timeout(1500)  # 等待重定向落定
        final_url = page.url
        self.browser.record_redirect(url)
        self.browser.record_redirect(final_url)
        self.target_domain = registered_domain(final_url)
        self._from_storage("redirect", "重定向链",
                           json.dumps(self.browser.redirect_chain,
                                      ensure_ascii=False))
        return json.dumps({
            "ok": True,
            "requested_url": url,
            "final_url": final_url,
            "http_status": resp.status if resp else None,
            "redirect_chain": self.browser.redirect_chain,
            "title": page.title(),
        }, ensure_ascii=False)

    def get_page_text(self) -> str:
        page = self.browser.page
        title = page.title()
        body = page.evaluate(
            "() => document.body ? document.body.innerText : ''")
        total = len(body)
        summary = body[: self.page_text_max]
        self._from_storage("text", "页面文本摘要",
                           f"[title] {title}\n{summary}")
        return json.dumps({
            "title": title,
            "text_total_chars": total,
            "summary": summary,
            "note": "text_total_chars 远大于 summary 长度说明页面以图片为主",
        }, ensure_ascii=False)

    def get_forms(self) -> str:
        page = self.browser.page
        page_domain = self.browser.page.url.split("//", 1)[-1].split("/", 1)[0]
        forms = page.evaluate("""
() => Array.from(document.forms).map(f => ({
  action: f.action, method: (f.method || 'get').toUpperCase(),
  fields: Array.from(f.elements).map(el => ({
    name: el.name || '', type: el.type || '',
    placeholder: el.placeholder || '', required: el.required || false
  }))
}))
""")
        out = []
        for i, f in enumerate(forms):
            action_host = (f["action"] or "").split("//", 1)[-1].split("/", 1)[0]
            out.append({
                "index": i,
                "action": f["action"],
                "method": f["method"],
                "action_domain_matches_page": (
                    not action_host or action_host == page_domain),
                "fields": [{
                    "name": fl["name"], "type": fl["type"],
                    "is_password": fl["type"] == "password",
                    "is_code_like": self._is_code_field(
                        fl["name"], fl["type"], fl["placeholder"]),
                } for fl in f["fields"]],
            })
        if out:
            self._from_storage("form", "表单枚举", json.dumps(out, ensure_ascii=False))
        return json.dumps({"forms": out}, ensure_ascii=False)

    def fill_form_test(self, form_index: int) -> str:
        page = self.browser.page
        forms = page.locator("form")
        if form_index >= forms.count():
            return json.dumps({"ok": False,
                               "error": f"表单序号 {form_index} 不存在"},
                              ensure_ascii=False)
        form = forms.nth(form_index)
        filled, skipped = [], []
        inputs = form.locator("input, textarea")
        for i in range(inputs.count()):
            el = inputs.nth(i)
            try:
                if not el.is_visible():
                    continue
                ftype = (el.get_attribute("type") or "text").lower()
                name = el.get_attribute("name") or ""
                placeholder = el.get_attribute("placeholder") or ""
                if ftype in ("hidden", "submit", "button", "image", "file", "checkbox", "radio"):
                    continue
                if self._is_code_field(name, ftype, placeholder):
                    # 验证码字段：填占位符并记录，绝不绕过
                    el.fill("123456")
                    skipped.append({"name": name, "reason": "验证码类字段，仅填占位符"})
                    continue
                key = ftype if ftype in FAKE_DATA else \
                    ("email" if "@" in placeholder else "text")
                el.fill(FAKE_DATA.get(key, FAKE_DATA["text"]))
                filled.append({"name": name, "type": ftype, "filled_as": key})
            except Exception as e:  # noqa: BLE001
                skipped.append({"name": name or f"input#{i}", "reason": str(e)[:80]})

        # 观察 3 秒内的弹窗/提示
        dialogs, page_msg = [], []
        page.on("dialog", lambda d: (dialogs.append(d.message()), d.dismiss()))
        page.wait_for_timeout(3000)
        for sel in (".alert", ".error", ".tip", "[role=alert]", ".el-message",
                    ".layui-layer-content"):
            try:
                for loc in page.locator(sel).all():
                    t = loc.inner_text().strip()
                    if t:
                        page_msg.append(t[:200])
            except Exception:  # noqa: BLE001
                pass
        result = {"ok": True, "filled": filled, "skipped": skipped,
                  "dialogs_3s": dialogs, "page_messages_3s": page_msg[:10],
                  "note": "数据未提交，仅在本地填充"}
        self._from_storage("form", f"表单{form_index}假数据填充", json.dumps(result, ensure_ascii=False))
        if page_msg or dialogs:
            self.signals.setdefault("fill_feedback", []).extend(page_msg + dialogs)
        return json.dumps(result, ensure_ascii=False)

    def submit_intercepted(self, form_index: int) -> str:
        """拦截式提交探测（§6.2 安全边界）。

        关键顺序：先注册 route(abort)，再点击 submit —— 请求不出网。
        """
        page = self.browser.page
        forms = page.locator("form")
        if form_index >= forms.count():
            return json.dumps({"ok": False,
                               "error": f"表单序号 {form_index} 不存在"},
                              ensure_ascii=False)

        intercepted_state = {"route_ready": False, "aborted": 0,
                             "failed": False}

        def _abort(_route):
            intercepted_state["aborted"] += 1
            _route.abort()

        # 1) 先注册网络层拦截 —— 必须在 click 之前
        try:
            page.route("**/*", _abort)
            intercepted_state["route_ready"] = True
        except Exception as e:  # noqa: BLE001
            intercepted_state["failed"] = True
            log.error("网络层拦截注册失败，立即中止提交探测: %s", e)
            return json.dumps({"ok": False, "intercepted": False,
                               "error": f"拦截注册失败，已中止: {e}"},
                              ensure_ascii=False)

        # 快照页面内容：abort 导致的失败导航会用错误页替换当前文档，
        # 点击后需据此恢复现场
        snapshot = page.content()

        # 2) 真实点击 submit（此时请求必被 abort，不出网）
        submit = forms.nth(form_index).locator(
            "input[type=submit], button[type=submit], button:not([type])").first
        click_error = None
        dialogs = []
        page.on("dialog", lambda d: (dialogs.append(d.message()), d.dismiss()))
        try:
            submit.click(timeout=5000)
            page.wait_for_timeout(2000)
        except Exception as e:  # noqa: BLE001
            click_error = str(e)[:200]

        # 3) 前端校验反馈与提交意图（需在恢复现场前读取错误前状态）
        url_after_click_raw = page.url
        page_destroyed = url_after_click_raw.startswith("chrome-error") or \
            url_after_click_raw.startswith("about:blank")
        validation = page.evaluate(
            "() => Array.from(document.querySelectorAll(':invalid'))"
            ".map(e => e.validationMessage).filter(Boolean)")
        page_msg = []
        for sel in (".alert", ".error", ".tip", "[role=alert]", ".el-message"):
            try:
                for loc in page.locator(sel).all():
                    t = loc.inner_text().strip()
                    if t:
                        page_msg.append(t[:200])
            except Exception:  # noqa: BLE001
                pass

        # 4) 撤销拦截并恢复现场
        try:
            page.unroute("**/*", _abort)
        except Exception:  # noqa: BLE001
            pass
        if page_destroyed:
            try:
                page.set_content(snapshot, wait_until="load")
            except Exception:  # noqa: BLE001
                log.exception("页面现场恢复失败")

        ok = intercepted_state["route_ready"] and not intercepted_state["failed"]
        result = {
            "ok": ok,
            "intercepted": intercepted_state["route_ready"],
            "requests_aborted": intercepted_state["aborted"],
            "click_error": click_error,
            "submit_intent_url": forms.nth(form_index).evaluate(
                "f => f.action") if forms.count() > form_index else None,
            "validation_messages": validation[:10],
            "page_messages": page_msg[:10],
            "dialogs": dialogs,
            "url_after_click": url_after_click_raw,
            "page_restored": page_destroyed,
            "note": "所有出站请求已在网络层 abort，表单数据未到达目标服务器",
        }
        if not ok:
            log.error("submit_intercepted 拦截状态异常，已中止: %s", result)
        self._from_storage("form", f"表单{form_index}拦截式提交探测",
                           json.dumps(result, ensure_ascii=False))
        return json.dumps(result, ensure_ascii=False)

    def get_external_resources(self) -> str:
        page = self.browser.page
        res = page.evaluate("""
() => {
  const host = location.host;
  const collect = sel => Array.from(document.querySelectorAll(sel))
    .map(e => e.src || e.href || e.action || '')
    .filter(Boolean);
  return {
    scripts: collect('script[src]'), imgs: collect('img[src]'),
    forms: Array.from(document.forms).map(f => f.action).filter(Boolean)
  };
}
""")
        page_domain = page.url.split("//", 1)[-1].split("/", 1)[0]

        def host_of(u: str) -> str:
            return u.split("//", 1)[-1].split("/", 1)[0].split(":")[0]

        third = sorted({host_of(u) for group in res.values() for u in group
                        if u and host_of(u) and host_of(u) != page_domain})
        self.static_domains = set(third)
        self._from_storage("tool_result", "第三方资源域名",
                           json.dumps(third, ensure_ascii=False))
        return json.dumps({"third_party_domains": third}, ensure_ascii=False)

    def screenshot(self) -> str:
        path = self.browser.screenshot(full_page=True)
        self._from_storage("screenshot", "整页截图", path)
        return json.dumps({"ok": True, "path": path}, ensure_ascii=False)

    def check_whois(self) -> str:
        from precheck.static_filter import whois_age_days
        from precheck.url_guard import registered_domain
        domain = registered_domain(self.browser.page.url)
        age = whois_age_days(domain)
        registrar = None
        try:
            import whois as whois_lib
            w = whois_lib.whois(domain)
            registrar = w.registrar if isinstance(w.registrar, str) else None
        except Exception:  # noqa: BLE001
            pass
        result = {"domain": domain, "age_days": age, "registrar": registrar,
                  "note": "查询失败时字段为 None，不中断流程"}
        self._from_storage("whois", "whois 注册信息",
                           json.dumps(result, ensure_ascii=False))
        return json.dumps(result, ensure_ascii=False)

    def finish(self, summary: str) -> str:
        self.finished = True
        self.signals["agent_summary"] = summary
        return json.dumps({"ok": True, "note": "agent 结束"},
                          ensure_ascii=False)

    # ---------- dispatch ----------
    def dispatch(self, name: str, args: dict) -> str:
        """按工具名分发调用，统一异常兜底（返回 JSON 错误而非中断）。"""
        fn = getattr(self, name, None)
        if not callable(fn):
            return json.dumps({"error": f"unknown tool: {name}"},
                              ensure_ascii=False)
        try:
            return fn(**args)
        except TypeError as e:
            return json.dumps({"error": f"bad args for {name}: {e}"},
                              ensure_ascii=False)
        except Exception as e:  # noqa: BLE001
            log.exception("工具 %s 执行失败", name)
            return json.dumps({"error": f"tool {name} failed: {e}"},
                              ensure_ascii=False)
