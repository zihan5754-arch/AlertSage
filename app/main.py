"""兼容 v0.1 的启动方式：

    uvicorn app.main:app --reload

真正实现在 alertsage.api.fastapi_app。保留这个文件是为了让 README 里
老命令仍然可用，迁移不需要改部署脚本。
"""

from __future__ import annotations

from alertsage.api.fastapi_app import create_app

app = create_app()

__all__ = ["app"]
