"""零依赖 HTTP 服务（基于标准库 http.server）。

存在的理由很实际：甲方跳板机/离线环境装不了 fastapi，但 python 自带 http.server。
它只用于演示和内网小规模调用，生产环境用 api.fastapi_app。
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlparse

from .. import __version__
from ..errors import AlertsageError, NormalizeError
from ..pipeline import TriagePipeline

MAX_BODY_BYTES = 2 * 1024 * 1024


class AlertsageHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address: tuple[str, int], pipeline: TriagePipeline) -> None:
        super().__init__(address, AlertSageHandler)
        self.pipeline = pipeline
        # 检测器与关联器带内部状态，HTTP 并发时必须串行化
        self.lock = threading.Lock()


class AlertSageHandler(BaseHTTPRequestHandler):
    server: AlertsageHTTPServer
    server_version = f"AlertSage/{__version__}"

    # ---------------------------------------------------------- 工具
    def log_message(self, fmt: str, *args: Any) -> None:  # noqa: A003
        if getattr(self.server, "verbose", False):  # pragma: no cover
            super().log_message(fmt, *args)

    def _send(self, status: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _read_json(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0:
            raise ValueError("请求体为空")
        if length > MAX_BODY_BYTES:
            raise ValueError(f"请求体超过 {MAX_BODY_BYTES} 字节")
        raw = self.rfile.read(length)
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError(f"请求体不是合法 JSON: {exc}") from exc
        if not isinstance(payload, dict):
            raise ValueError("请求体必须是 JSON 对象")
        return payload

    # ---------------------------------------------------------- 路由
    def do_OPTIONS(self) -> None:  # noqa: N802
        self._send(204, {})

    def do_HEAD(self) -> None:  # noqa: N802
        self.do_GET()

    def do_GET(self) -> None:  # noqa: N802
        path = urlparse(self.path).path.rstrip("/") or "/"
        pipeline = self.server.pipeline
        if path in ("/", "/health"):
            self._send(
                200,
                {
                    "service": "alertsage",
                    "version": __version__,
                    "status": "ok",
                    "rules": len(pipeline.rules),
                    "detectors": [getattr(d, "name", "?") for d in pipeline.detectors],
                    "llm": {
                        "enabled": pipeline.settings.llm_enabled,
                        "provider": pipeline.settings.llm_provider,
                    },
                },
            )
            return
        if path == "/rules":
            self._send(
                200,
                {
                    "total": len(pipeline.rules),
                    "rules": [
                        {
                            "id": r.id,
                            "title": r.title,
                            "severity": r.severity,
                            "category": r.category,
                            "mitre": r.mitre,
                        }
                        for r in pipeline.rules
                    ],
                },
            )
            return
        self._send(404, {"error": "not_found", "path": path})

    def do_POST(self) -> None:  # noqa: N802
        path = urlparse(self.path).path.rstrip("/") or "/"
        pipeline = self.server.pipeline
        try:
            payload = self._read_json()
        except ValueError as exc:
            self._send(400, {"error": "bad_request", "detail": str(exc)})
            return

        try:
            if path == "/triage":
                alert = payload.get("alert", payload)
                source = payload.get("source") if isinstance(payload.get("alert"), dict) else None
                with self.server.lock:
                    result = pipeline.triage_raw(alert, source)
                self._send(200, {"result": result.to_dict()})
                return

            if path == "/triage/batch":
                alerts = payload.get("alerts")
                if not isinstance(alerts, list):
                    self._send(422, {"error": "invalid_payload", "detail": "alerts 必须是数组"})
                    return
                with self.server.lock:
                    results, summary = pipeline.triage_batch(alerts, payload.get("source"))
                self._send(
                    200,
                    {"results": [r.to_dict() for r in results], "summary": summary},
                )
                return

            self._send(404, {"error": "not_found", "path": path})
        except NormalizeError as exc:
            self._send(422, {"error": "normalize_error", "detail": str(exc)})
        except AlertsageError as exc:
            self._send(400, {"error": "alertsage_error", "detail": str(exc)})
        except Exception as exc:  # noqa: BLE001
            self._send(500, {"error": "internal_error", "detail": f"{type(exc).__name__}: {exc}"})


def make_server(
    pipeline: TriagePipeline, host: str = "127.0.0.1", port: int = 8000
) -> AlertsageHTTPServer:
    return AlertsageHTTPServer((host, port), pipeline)


def run_server(
    pipeline: TriagePipeline, host: str = "127.0.0.1", port: int = 8000, verbose: bool = False
) -> None:
    server = make_server(pipeline, host, port)
    server.verbose = verbose  # type: ignore[attr-defined]
    print(f"AlertSage {__version__} 已启动: http://{host}:{server.server_address[1]}")
    print("  GET  /health | GET /rules | POST /triage | POST /triage/batch")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n已停止")
    finally:
        server.server_close()
