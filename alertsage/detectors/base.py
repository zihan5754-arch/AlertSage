"""检测器基类与注册表。

新增检测能力 = 新增一个实现 Detector 的类，然后在 build_detectors 里挂上，
不用改 pipeline 和打分逻辑。这是"可扩展"落到代码里的样子。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

from ..config import Settings
from ..models import Alert, Detection


@dataclass(slots=True)
class DetectorContext:
    """一次研判过程中会传给所有检测器的共享状态。"""

    settings: Settings
    state: dict = field(default_factory=dict)


@runtime_checkable
class Detector(Protocol):
    name: str

    def detect(self, alert: Alert, ctx: DetectorContext) -> list[Detection]: ...
