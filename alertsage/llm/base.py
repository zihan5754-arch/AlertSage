"""LLM Provider 抽象。

为什么要有这层：公司里可能用 OpenAI、Azure、通义、DeepSeek、或者内网 vLLM，
接口都差不多但不完全一样。抽象出 complete(system, user) -> str 之后，
换供应商只改一个配置，不动业务代码。
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable


@runtime_checkable
class LLMProvider(Protocol):
    name: str

    def complete(self, system_prompt: str, user_prompt: str) -> str:
        """返回模型原始文本（约定是 JSON 字符串）。失败时抛 LLMError。"""
        ...
