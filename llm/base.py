"""LLMProvider 抽象接口 —— 所有大模型调用的唯一入口。

业务代码（agent 循环、研判模块）只依赖此接口，不 import 任何具体 SDK。
切换本地部署模型 = 改 config.yaml 的 provider 配置，业务代码零改动。
"""
from __future__ import annotations

from abc import ABC, abstractmethod


class UnsupportedCapabilityError(RuntimeError):
    """当前 provider 不支持所请求的能力（如视觉）。"""


class ContentModerationError(RuntimeError):
    """云端模型内容审核拦截输入（如 data_inspection_failed）。

    重试无意义，上层应走降级路径而非让整个任务失败。
    """


class LLMProvider(ABC):
    """所有大模型调用的唯一入口。"""

    #: 配置中显式声明，研判模块据此选择"文本+截图"或"纯文本+本地标注"路径
    supports_vision: bool = False

    @abstractmethod
    def chat(self, messages: list[dict], tools: list[dict] | None = None,
             temperature: float = 0.2) -> dict:
        """纯文本对话 / function calling 循环中的单步调用。

        messages: OpenAI 格式 [{"role": ..., "content": ...}]
        tools:    OpenAI 格式的工具定义列表（agent 循环用）
        返回:     {"content": str|None, "tool_calls": list|None, "usage": {...}}
        """

    @abstractmethod
    def chat_with_image(self, messages: list[dict],
                        image_paths: list[str]) -> dict:
        """带截图的视觉调用。image_paths 为本地图片绝对路径。

        返回格式同 chat()。不支持视觉的 provider 应抛出
        UnsupportedCapabilityError，由上层降级为纯文本路径。
        """

    @property
    @abstractmethod
    def model_name(self) -> str:
        """当前文本模型名（用于日志与展示）。"""

    @property
    @abstractmethod
    def vision_model_name(self) -> str:
        """当前视觉模型名。"""
