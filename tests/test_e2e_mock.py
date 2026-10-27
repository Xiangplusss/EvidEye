"""端到端 mock 测试：脚本化假 LLM 驱动完整 pipeline（黑名单路径）。

验证：预检 → 黑名单一票判定 → 跳过 agent → 综合研判（mock）→ HTML 报告落盘。
不依赖真实 API key、不访问外网恶意站点。
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

import yaml  # noqa: E402


class MockProvider:
    """脚本化 provider：研判段返回固定 JSON。"""
    supports_vision = True

    @property
    def model_name(self):
        return "mock-text"

    @property
    def vision_model_name(self):
        return "mock-vision"

    def chat(self, messages, tools=None, temperature=0.2, task_id=None,
             purpose="agent"):
        return {"content": json.dumps({
            "score": 92, "level": "high",
            "dimensions": {"url": 30, "tech": 25, "content": 28,
                           "behavior": 15},
            "evidence": ["域名命中内置黑名单（一票判定）",
                         "静态预筛 URL 特征信号已汇总",
                         "维度评分来自 mock provider，仅验证链路"],
            "risk_reasons": [
                {"category": "可疑域名", "reason": "域名命中内置黑名单",
                 "evidence": "blacklist_hit=true, domain=example.com"},
                {"category": "钓鱼特征", "reason": "mock 端到端验证钓鱼特征归类",
                 "evidence": "mock"}],
            "confidence": 0.9,
            "summary": "mock 端到端测试结论"},
            ensure_ascii=False),
            "tool_calls": None, "usage": {"prompt_tokens": 100,
                                          "completion_tokens": 50}}

    def chat_with_image(self, messages, image_paths, task_id=None,
                        purpose="vision"):
        return self.chat(messages, task_id=task_id, purpose=purpose)


def main() -> int:
    import pipeline
    cfg = pipeline.load_config()

    # 临时配置：把 example.com 加进黑名单（该域名可公网解析，预检可通过）
    bl = ROOT / "data/test-blacklist.txt"
    bl.write_text("example.com\n", encoding="utf-8")
    cfg["precheck"]["blacklist_file"] = str(bl)
    cfg["storage"]["db_path"] = "data/e2e-mock.db"
    cfg["storage"]["report_dir"] = "static/reports"

    # 注入 mock provider
    pipeline.create_provider_with_retry_log = lambda c, d: MockProvider()

    result = pipeline.analyze_url("http://example.com/?utm_source=x", cfg)
    assert result["ok"], result.get("error")
    rep = result["report"]
    assert rep["score"] == 92 and rep["level"] == "high"
    assert rep["isolation_level"] == "skipped (blacklist)"  # 黑名单命中跳过 agent
    assert len(rep["evidence"]) >= 3
    assert len(rep["redirect_chain"]) >= 1
    assert any("黑名单" in e for e in rep["evidence"])
    assert Path(result["report_path"]).exists()
    html = Path(result["report_path"]).read_text(encoding="utf-8")
    assert "mock 端到端测试结论" in html and "高风险" in html
    assert "不可信原因分析" in html and "可疑域名" in html and "钓鱼特征" in html
    print(f"[OK] 端到端 mock: score=92/high, 报告={result['report_path']}")

    # 预检拒绝路径：内网 URL
    result2 = pipeline.analyze_url("http://192.168.1.1/admin", cfg)
    assert not result2["ok"] and "拒绝" in result2["error"]
    print(f"[OK] 内网 URL 正确拒绝: {result2['error']}")

    print("\n端到端 mock 测试全部通过 ✓")
    return 0


if __name__ == "__main__":
    sys.exit(main())
