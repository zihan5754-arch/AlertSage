import re
from typing import Optional
from app.models.schemas import AlertInput, AlertVerdict

ATTACK_PATTERNS = [
    {
        "name": "SQL Injection",
        "pattern": re.compile(r"('|\")\s*(or|and)\s+\d+\s*=\s*\d+", re.I),
        "severity": "high",
        "analysis": "检测到 SQL 注入永真式攻击模式。",
        "recommendation": [
            "检查目标参数是否使用参数化查询",
            "封禁来源 IP",
            "排查是否有成功注入痕迹"
        ]
    },
    {
        "name": "XSS",
        "pattern": re.compile(r"<script.*?>|javascript:|onerror\s*=", re.I),
        "severity": "medium",
        "analysis": "检测到 XSS 攻击特征。",
        "recommendation": [
            "对输出进行 HTML 编码",
            "检查输入过滤规则"
        ]
    },
    {
        "name": "Command Injection",
        "pattern": re.compile(r"[;&|`]\s*(cat|ls|whoami|id|curl|wget|bash|sh)\b", re.I),
        "severity": "high",
        "analysis": "检测到命令注入特征。",
        "recommendation": [
            "检查命令执行接口",
            "封禁来源 IP",
            "限制服务权限"
        ]
    },
    {
        "name": "Path Traversal",
        "pattern": re.compile(r"\.\./|\.\.\\", re.I),
        "severity": "medium",
        "analysis": "检测到路径穿越特征。",
        "recommendation": [
            "检查文件读取接口",
            "规范化路径输入"
        ]
    },
    {
        "name": "Scanner",
        "pattern": re.compile(r"(nikto|nmap|sqlmap|acunetix|nessus)", re.I),
        "severity": "low",
        "analysis": "疑似扫描器探测。",
        "recommendation": [
            "观察该 IP 后续行为",
            "必要时临时封禁"
        ]
    }
]


def detect_by_regex(alert: AlertInput) -> Optional[AlertVerdict]:
    text = " ".join(filter(None, [alert.payload, alert.raw_log, alert.target_url]))

    for rule in ATTACK_PATTERNS:
        if rule["pattern"].search(text):
            return AlertVerdict(
                verdict="true_positive",
                attack_type=rule["name"],
                severity=rule["severity"],
                confidence=0.8,
                analysis=rule["analysis"],
                recommendation=rule["recommendation"],
                false_positive_likelihood="low"
            )
    return None
