from pydantic import BaseModel, Field
from typing import List, Optional


class AlertInput(BaseModel):
    alert_type: str = Field(..., description="告警类型，如 SQL Injection")
    source_ip: str = Field(..., description="来源 IP")
    target_url: Optional[str] = Field(None, description="目标 URL")
    payload: Optional[str] = Field(None, description="攻击 payload")
    raw_log: Optional[str] = Field(None, description="原始日志")
    timestamp: Optional[str] = Field(None, description="告警时间")


class AlertVerdict(BaseModel):
    verdict: str = Field(..., description="true_positive / false_positive / unknown")
    attack_type: str = Field(..., description="攻击类型")
    severity: str = Field(..., description="low / medium / high / critical")
    confidence: float = Field(..., ge=0.0, le=1.0, description="置信度")
    analysis: str = Field(..., description="简要分析")
    recommendation: List[str] = Field(..., description="处置建议")
    false_positive_likelihood: str = Field(..., description="low / medium / high")
