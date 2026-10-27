"""OpenAICompatProvider —— 一个类同时服务 Qwen(DashScope) 与本地 OpenAI 兼容后端
（vLLM / Ollama / llama.cpp server），仅 base_url / key / 模型名不同。

统一封装：超时、指数退避重试、调用日志（写入 SQLite，只记 token 用量）。
"""
from __future__ import annotations

import base64
import json
import logging
import time
from pathlib import Path

from openai import OpenAI

from .base import LLMProvider, ContentModerationError, UnsupportedCapabilityError

log = logging.getLogger(__name__)


def _encode_image_data_url(path: str) -> str:
    data = Path(path).read_bytes()
    suffix = Path(path).suffix.lower().lstrip(".")
    mime = {"jpg": "image/jpeg", "jpeg": "image/jpeg", "png": "image/png",
            "webp": "image/webp", "gif": "image/gif"}.get(suffix, "image/png")
    return f"data:{mime};base64,{base64.b64encode(data).decode()}"


class OpenAICompatProvider(LLMProvider):
    def __init__(self, cfg: dict, call_logger=None):
        """
        cfg: config.yaml 中 llm.qwen / llm.local 段
        call_logger: callable(task_id, model, purpose, prompt_chars, usage,
                              duration_ms, ok, error) 用于调用日志入库
        """
        self.base_url = cfg["base_url"]
        api_key_env = cfg.get("api_key_env") or ""
        import os
        self.api_key = os.environ.get(api_key_env, "") if api_key_env else "local"
        if api_key_env and not self.api_key:
            raise RuntimeError(
                f"未设置环境变量 {api_key_env}。请先配置 API key，例如：\n"
                f"  PowerShell: $env:{api_key_env} = 'sk-...'\n"
                f"  Git Bash  : export {api_key_env}=sk-...\n"
                "（切换本地模型时将 llm.provider 改为 local 即无需 key）")
        self.text_model = cfg["text_model"]
        self.vision_model = cfg.get("vision_model", cfg["text_model"])
        self.supports_vision = bool(cfg.get("supports_vision", False))
        self.max_context_tokens = int(cfg.get("max_context_tokens", 32000))
        self.timeout = int(cfg.get("timeout_seconds", 60))
        self.max_retries = int(cfg.get("max_retries", 3))
        self.backoff_base = float(cfg.get("backoff_base_seconds", 1.5))
        self._client = OpenAI(base_url=self.base_url, api_key=self.api_key,
                              timeout=self.timeout)
        self._call_logger = call_logger

    # ---- properties ----
    @property
    def model_name(self) -> str:
        return self.text_model

    @property
    def vision_model_name(self) -> str:
        return self.vision_model

    # ---- public API ----
    def chat(self, messages: list[dict], tools: list[dict] | None = None,
             temperature: float = 0.2, task_id: str | None = None,
             purpose: str = "agent") -> dict:
        return self._call(self.text_model, messages, tools, temperature,
                          task_id, purpose)

    def chat_with_image(self, messages: list[dict], image_paths: list[str],
                        task_id: str | None = None,
                        purpose: str = "vision") -> dict:
        if not self.supports_vision:
            raise UnsupportedCapabilityError(
                f"provider(base_url={self.base_url}) 未声明视觉能力，"
                "请在 config.yaml 中设置 supports_vision 或降级为纯文本路径")
        content: list[dict] = []
        # 取最后一条 user 文本消息 + 附加图片
        for msg in messages:
            if msg["role"] == "user":
                content.append({"type": "text", "text": msg["content"]})
        for p in image_paths:
            content.append({"type": "image_url",
                            "image_url": {"url": _encode_image_data_url(p)}})
        vision_messages = ([m for m in messages if m["role"] != "user"]
                           + [{"role": "user", "content": content}])
        return self._call(self.vision_model, vision_messages, None, 0.2,
                          task_id, purpose)

    # ---- internal ----
    def _call(self, model: str, messages: list[dict], tools: list[dict] | None,
              temperature: float, task_id: str | None, purpose: str) -> dict:
        prompt_chars = sum(len(json.dumps(m, ensure_ascii=False))
                           for m in messages)
        last_err: Exception | None = None
        for attempt in range(self.max_retries):
            start = time.time()
            try:
                kwargs: dict = {
                    "model": model,
                    "messages": messages,
                    "temperature": temperature,
                    "timeout": self.timeout,
                }
                if tools:
                    kwargs["tools"] = tools
                resp = self._client.chat.completions.create(**kwargs)
                duration_ms = int((time.time() - start) * 1000)
                usage = {"prompt_tokens": resp.usage.prompt_tokens if resp.usage else None,
                         "completion_tokens": resp.usage.completion_tokens if resp.usage else None}
                self._log(task_id, model, purpose, prompt_chars, usage,
                          duration_ms, True, None)
                return {
                    "content": resp.choices[0].message.content,
                    "tool_calls": [tc.model_dump()
                                   for tc in (resp.choices[0].message.tool_calls or [])] or None,
                    "usage": usage,
                }
            except UnsupportedCapabilityError:
                raise
            except Exception as e:  # noqa: BLE001
                last_err = e
                duration_ms = int((time.time() - start) * 1000)
                self._log(task_id, model, purpose, prompt_chars, None,
                          duration_ms, False, str(e))
                # 内容审核拦截：重试无意义，立即抛专用异常走降级
                if "data_inspection_failed" in str(e).lower():
                    raise ContentModerationError(str(e)[:300]) from e
                if attempt < self.max_retries - 1:
                    sleep_s = self.backoff_base ** attempt
                    log.warning("LLM 调用失败(第 %d 次): %s，%.1fs 后重试",
                                attempt + 1, e, sleep_s)
                    time.sleep(sleep_s)
        raise RuntimeError(f"LLM 调用在 {self.max_retries} 次重试后仍失败: {last_err}")

    def _log(self, task_id, model, purpose, prompt_chars, usage, duration_ms,
             ok, error):
        log.debug("llm call task=%s model=%s ok=%s %dms", task_id, model, ok,
                  duration_ms)
        if self._call_logger:
            try:
                self._call_logger(task_id, model, purpose, prompt_chars,
                                  usage or {}, duration_ms, ok, error)
            except Exception:  # noqa: BLE001
                log.exception("调用日志写入失败")
