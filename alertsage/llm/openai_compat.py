"""OpenAI 兼容 Provider（只用标准库 urllib，不引入 openai SDK）。

兼容面：OpenAI / DeepSeek / 通义 / 智谱 / vLLM / Ollama 的 /v1/chat/completions。
只实现"发一条消息拿回一段文本"，够用且不重。
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request

from ..errors import LLMError


class OpenAICompatProvider:
    name = "openai"

    def __init__(
        self,
        base_url: str,
        api_key: str,
        model: str,
        timeout: float = 20.0,
        max_retries: int = 1,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.model = model
        self.timeout = timeout
        self.max_retries = max(0, max_retries)

    def _endpoint(self) -> str:
        if self.base_url.endswith("/chat/completions"):
            return self.base_url
        return self.base_url + "/chat/completions"

    def complete(self, system_prompt: str, user_prompt: str) -> str:
        body = {
            "model": self.model,
            "temperature": 0.2,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "response_format": {"type": "json_object"},
        }
        data = json.dumps(body, ensure_ascii=False).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}",
        }

        last_error: Exception | None = None
        for attempt in range(self.max_retries + 1):
            request = urllib.request.Request(
                self._endpoint(), data=data, headers=headers, method="POST"
            )
            try:
                with urllib.request.urlopen(request, timeout=self.timeout) as resp:
                    payload = json.loads(resp.read().decode("utf-8"))
                content = payload["choices"][0]["message"]["content"]
                if not content:
                    raise LLMError("模型返回空内容")
                return str(content)
            except (urllib.error.URLError, TimeoutError, OSError) as exc:
                last_error = exc
            except (KeyError, IndexError, json.JSONDecodeError) as exc:
                raise LLMError(f"模型响应格式异常: {exc}") from exc
            if attempt < self.max_retries:
                time.sleep(min(2**attempt * 0.5, 3.0))

        raise LLMError(f"LLM 调用失败: {last_error}")
