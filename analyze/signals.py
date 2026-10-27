"""信号汇总与规则评分引擎（0-100，与 LLM 结论并行输出、互为校验）。

维度（方案 §6.3）：
- URL 特征 30 分：来自静态预筛
- 技术特征 25 分：表单/HTTP/重定向等技术信号
- 内容特征 30 分：由 LLM 研判回填
- 交互特征 15 分：由 agent 交互探测结果回填
黑名单命中直接 100 并跳过 agent。
"""
from __future__ import annotations


def score_tech(tech_signals: dict) -> int:
    """技术特征评分（0-25）。

    tech_signals 可含:
      form_action_third_party: bool  表单提交到第三方域名
      password_outside_login: bool   非登录语境出现密码框
      http_form: bool                HTTP 明文表单
      redirect_jumps: int            重定向跳数
    """
    s = 0
    if tech_signals.get("form_action_third_party"):
        s += 10
    if tech_signals.get("password_outside_login"):
        s += 6
    if tech_signals.get("http_form"):
        s += 4
    jumps = tech_signals.get("redirect_jumps") or 0
    if jumps > 3:
        s += 5
    return min(25, s)


def score_interaction(agent_result: dict) -> int:
    """交互特征评分（0-15）。填假数据后出现缴费/下载要求等。"""
    s = 0
    feedback = " ".join(agent_result.get("fill_feedback", [])).lower()
    keywords = ("缴费", "支付", "充值", "下载", "安装", "转账", "验证码",
                "手续费", "解冻", "payment", "download", "install")
    if any(k in feedback for k in keywords):
        s += 10
    submit_probe = agent_result.get("submit_probe") or {}
    if submit_probe.get("intercepted") and (
            submit_probe.get("requests_aborted", 0) > 0
            and not submit_probe.get("validation_messages")):
        # 前端无校验、直接尝试发出请求 —— 典型钓鱼表单行为
        s += 5
    return min(15, s)


def rule_score(prefilter: dict, tech_signals: dict,
               agent_result: dict) -> dict:
    """汇总规则分。content 维度由 LLM 回填前记 0，最终报告以研判结果为准。"""
    if prefilter.get("blacklist_hit"):
        return {"url": 30, "tech": 25, "content": 30, "behavior": 15,
                "total": 100, "blacklist_hit": True}
    url = min(30, prefilter.get("url_score", 0))
    tech = score_tech(tech_signals)
    behavior = score_interaction(agent_result)
    return {"url": url, "tech": tech, "content": 0, "behavior": behavior,
            "total": url + tech + behavior, "blacklist_hit": False}


def merge_llm_dimensions(rule_dims: dict, llm_dims: dict) -> dict:
    """内容维度以 LLM 为准，其余维度取规则分与 LLM 分的较大者（互为校验）。"""
    merged = {}
    for k, cap in (("url", 30), ("tech", 25), ("content", 30),
                   ("behavior", 15)):
        r = rule_dims.get(k, 0)
        l = llm_dims.get(k, 0)
        merged[k] = max(r, l) if k != "content" else min(cap, l)
    merged["total"] = sum(merged[k] for k in
                          ("url", "tech", "content", "behavior"))
    return merged
