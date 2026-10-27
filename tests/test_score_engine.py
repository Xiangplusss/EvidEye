"""评分引擎单元测试（方案 S3 验收：黑名单一票判定）。"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from analyze.signals import (  # noqa: E402
    merge_llm_dimensions, rule_score, score_interaction, score_tech)


def test_blacklist_one_vote():
    prefilter = {"blacklist_hit": True, "url_score": 0}
    r = rule_score(prefilter, {}, {})
    assert r["total"] == 100 and r["blacklist_hit"]


def test_tech_score():
    s = score_tech({"form_action_third_party": True,
                    "password_outside_login": True,
                    "http_form": True, "redirect_jumps": 5})
    assert s == 25  # 10+6+4+5
    assert score_tech({}) == 0
    assert score_tech({"redirect_jumps": 3}) == 0  # ≤3 跳不扣


def test_interaction_score():
    s = score_interaction({"fill_feedback": ["请先缴纳手续费"],
                           "submit_probe": {"intercepted": True,
                                            "requests_aborted": 2,
                                            "validation_messages": []}})
    assert s == 15
    assert score_interaction({"fill_feedback": []}) == 0


def test_rule_score_caps():
    r = rule_score({"blacklist_hit": False, "url_score": 45},  # 超上限
                   {"form_action_third_party": True}, {})
    assert r["url"] == 30 and r["tech"] == 10


def test_merge_llm_dimensions():
    merged = merge_llm_dimensions(
        {"url": 20, "tech": 10, "content": 0, "behavior": 5},
        {"url": 10, "tech": 20, "content": 25, "behavior": 3})
    # 非内容维度取较大者，内容维度以 LLM 为准
    assert merged == {"url": 20, "tech": 20, "content": 25, "behavior": 5,
                      "total": 70}
