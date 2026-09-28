from fastapi import FastAPI
from app.models.schemas import AlertInput, AlertVerdict
from app.detectors.regex_detector import detect_by_regex

app = FastAPI(
    title="AlertSage",
    description="蓝队告警智能研判助手",
    version="0.1.0"
)


@app.get("/")
def root():
    return {"message": "AlertSage is running"}


@app.post("/analyze", response_model=AlertVerdict)
def analyze_alert(alert: AlertInput):
    result = detect_by_regex(alert)
    if result:
        return result

    return AlertVerdict(
        verdict="unknown",
        attack_type="Unknown",
        severity="low",
        confidence=0.3,
        analysis="规则层未匹配到已知攻击特征，建议人工研判或后续接入 LLM 层。",
        recommendation=["人工复核告警", "查看关联日志"],
        false_positive_likelihood="medium"
    )
