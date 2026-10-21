"""FastAPI 应用（可选依赖）。

和 stdlib_server 暴露同样的四个接口，差别只是文档、校验和生态。
装 fastapi 就能用 /docs 直接给面试官演示。
"""

from __future__ import annotations

from typing import Any

from .. import __version__
from ..config import Settings
from ..errors import AlertsageError, NormalizeError
from ..pipeline import TriagePipeline


def create_app(pipeline: TriagePipeline | None = None, settings: Settings | None = None):
    try:
        from fastapi import Body, FastAPI, HTTPException
        from fastapi.middleware.cors import CORSMiddleware
    except ImportError as exc:  # pragma: no cover - 取决于环境
        raise RuntimeError(
            "未安装 fastapi/uvicorn。执行：pip install -r requirements-api.txt"
        ) from exc

    engine = pipeline or TriagePipeline(settings)
    app = FastAPI(
        title="AlertSage",
        description="面向蓝队的可解释告警研判引擎（规则 + 行为 + 可选 LLM）",
        version=__version__,
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.get("/health", summary="健康检查")
    def health() -> dict[str, Any]:
        return {
            "service": "alertsage",
            "version": __version__,
            "status": "ok",
            "rules": len(engine.rules),
            "detectors": [getattr(d, "name", "?") for d in engine.detectors],
            "llm": {"enabled": engine.settings.llm_enabled, "provider": engine.settings.llm_provider},
        }

    @app.get("/rules", summary="列出已加载规则")
    def list_rules() -> dict[str, Any]:
        return {
            "total": len(engine.rules),
            "rules": [
                {
                    "id": r.id,
                    "title": r.title,
                    "severity": r.severity,
                    "category": r.category,
                    "mitre": r.mitre,
                }
                for r in engine.rules
            ],
        }

    @app.post("/triage", summary="研判单条告警")
    def triage(payload: dict[str, Any] = Body(...)) -> dict[str, Any]:
        alert = payload.get("alert", payload)
        source = payload.get("source") if isinstance(payload.get("alert"), dict) else None
        try:
            return {"result": engine.triage_raw(alert, source).to_dict()}
        except NormalizeError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        except AlertsageError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/triage/batch", summary="批量研判")
    def triage_batch(payload: dict[str, Any] = Body(...)) -> dict[str, Any]:
        alerts = payload.get("alerts")
        if not isinstance(alerts, list):
            raise HTTPException(status_code=422, detail="alerts 必须是数组")
        results, summary = engine.triage_batch(alerts, payload.get("source"))
        return {"results": [r.to_dict() for r in results], "summary": summary}

    return app


def __getattr__(name: str):
    """允许 `from alertsage.api.fastapi_app import app` 懒加载。"""
    if name == "app":
        module_app = create_app()
        globals()["app"] = module_app
        return module_app
    raise AttributeError(name)
