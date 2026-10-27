"""配置驱动实例化：切换 provider 只改 config.yaml，不改业务代码。"""
from __future__ import annotations

from .base import LLMProvider
from .openai_compat import OpenAICompatProvider


def create_provider(cfg: dict, call_logger=None) -> LLMProvider:
    name = cfg["provider"]
    if name in ("qwen", "local"):
        # 两者均为 OpenAI 兼容协议，同一个实现类
        return OpenAICompatProvider(cfg[name], call_logger=call_logger)
    raise ValueError(f"unknown provider: {name}")


def create_provider_with_retry_log(cfg: dict, db_path: str) -> LLMProvider:
    """工厂便捷方法：把存储层的调用日志函数接到 provider。"""
    from storage import db

    def logger(task_id, model, purpose, prompt_chars, usage, duration_ms, ok,
               error):
        db.log_llm_call(db_path, task_id, cfg["provider"], model, purpose,
                        prompt_chars, usage, duration_ms, ok, error)

    return create_provider(cfg, call_logger=logger)
