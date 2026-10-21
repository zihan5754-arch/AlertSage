"""HTTP 接入层。

- stdlib_server：零依赖，离线可用；
- fastapi_app：生产/演示，带 /docs。
"""

from .stdlib_server import AlertsageHTTPServer, make_server, run_server

__all__ = ["AlertsageHTTPServer", "make_server", "run_server"]
