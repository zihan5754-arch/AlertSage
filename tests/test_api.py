"""HTTP 接口测试：直接起一个真实的标准库服务，不做 mock。

这样测的是"别人真正会调到的东西"，包括状态码、请求体校验、CORS 头。
"""

from __future__ import annotations

import json
import threading
import unittest
import urllib.error
import urllib.request

from alertsage.api.stdlib_server import make_server
from tests.helpers import make_pipeline

DEMO = {
    "alert_type": "SQL Injection",
    "timestamp": "2026-09-10T14:22:31+08:00",
    "src_ip": "45.134.26.17",
    "payload": "1 union select 1,2",
    "target_url": "/api/order",
}


class APITest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.server = make_server(make_pipeline(), "127.0.0.1", 0)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()

    # ---------------------------------------------------------- 工具
    def _get(self, path: str) -> tuple[int, dict, dict]:
        request = urllib.request.Request(f"http://127.0.0.1:{self.port}{path}")
        try:
            with urllib.request.urlopen(request, timeout=5) as resp:
                return resp.status, json.loads(resp.read().decode("utf-8")), dict(resp.headers)
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read().decode("utf-8") or "{}"), dict(exc.headers)

    def _post(self, path: str, payload, raw: bytes | None = None) -> tuple[int, dict]:
        body = raw if raw is not None else json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(
            f"http://127.0.0.1:{self.port}{path}",
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=5) as resp:
                return resp.status, json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read().decode("utf-8") or "{}")

    # ---------------------------------------------------------- 用例
    def test_health(self) -> None:
        status, body, headers = self._get("/health")
        self.assertEqual(status, 200)
        self.assertEqual(body["status"], "ok")
        self.assertGreaterEqual(body["rules"], 16)
        self.assertEqual(headers.get("Access-Control-Allow-Origin"), "*")

    def test_root_is_health(self) -> None:
        status, body, _ = self._get("/")
        self.assertEqual(status, 200)
        self.assertIn("version", body)

    def test_rules(self) -> None:
        status, body, _ = self._get("/rules")
        self.assertEqual(status, 200)
        self.assertGreaterEqual(body["total"], 16)
        self.assertIn("mitre", body["rules"][0])

    def test_triage(self) -> None:
        status, body = self._post("/triage", DEMO)
        self.assertEqual(status, 200)
        result = body["result"]
        self.assertEqual(result["verdict"], "true_positive")
        self.assertIn("evidence", result)

    def test_triage_accepts_wrapped_payload(self) -> None:
        status, body = self._post("/triage", {"alert": DEMO})
        self.assertEqual(status, 200)
        self.assertIn("result", body)

    def test_triage_batch(self) -> None:
        status, body = self._post("/triage/batch", {"alerts": [DEMO, DEMO]})
        self.assertEqual(status, 200)
        self.assertEqual(len(body["results"]), 2)
        self.assertEqual(body["summary"]["total"], 2)

    def test_bad_json_returns_400(self) -> None:
        status, body = self._post("/triage", None, raw=b"{not json")
        self.assertEqual(status, 400)
        self.assertEqual(body["error"], "bad_request")

    def test_batch_requires_list(self) -> None:
        status, body = self._post("/triage/batch", {"alerts": "nope"})
        self.assertEqual(status, 422)
        self.assertEqual(body["error"], "invalid_payload")

    def test_normalize_error_returns_422(self) -> None:
        status, body = self._post("/triage", {"timestamp": "昨天下午", "src_ip": "1.1.1.1"})
        self.assertEqual(status, 422)
        self.assertEqual(body["error"], "normalize_error")

    def test_unknown_path_404(self) -> None:
        status, body, _ = self._get("/nope")
        self.assertEqual(status, 404)
        self.assertEqual(body["error"], "not_found")

    def test_options_preflight(self) -> None:
        request = urllib.request.Request(
            f"http://127.0.0.1:{self.port}/triage", method="OPTIONS"
        )
        with urllib.request.urlopen(request, timeout=5) as resp:
            self.assertEqual(resp.status, 204)
            self.assertEqual(resp.headers.get("Access-Control-Allow-Methods"), "GET, POST, OPTIONS")


if __name__ == "__main__":
    unittest.main()
