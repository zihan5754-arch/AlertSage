"""命令行入口：alertsage <command>。

设计上把"能演示"当成一等需求：面试时一条 `alertsage demo` 就能把
从原始告警到报告的过程跑出来，比讲十分钟架构有效。
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from . import __version__
from .config import load_settings
from .errors import AlertsageError
from .evaluate import evaluate, load_labeled, render_eval_markdown
from .pipeline import TriagePipeline
from .report import write_report
from .rules import lint_rules, load_rules

VERDICT_LABEL = {
    "true_positive": "真实攻击",
    "false_positive": "疑似误报",
    "needs_review": "待人工复核",
}

DEMO_ALERT: dict[str, Any] = {
    "alert_type": "Web Attack - SQL Injection",
    "timestamp": "2026-09-10T14:22:31+08:00",
    "src_ip": "45.134.26.17",
    "dst_ip": "10.20.3.8",
    "dst_port": 443,
    "target_url": "/api/v1/order/detail?id=1%20union%20select%201,2,3,4--",
    "http_method": "GET",
    "status_code": 500,
    "user_agent": "sqlmap/1.7.2#stable (https://sqlmap.org)",
    "payload": "1 union select username,password from users--",
    "raw_log": '10.20.3.8 - - "GET /api/v1/order/detail?id=1 union select 1,2,3 HTTP/1.1" 500 512',
    "asset": "order-api",
    "action": "logged",
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="alertsage",
        description="AlertSage - 面向蓝队的可解释告警研判引擎",
    )
    parser.add_argument("--version", action="version", version=f"AlertSage {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    demo = sub.add_parser("demo", help="用内置样例告警跑一次完整研判")
    demo.add_argument("--json", action="store_true", help="输出完整 JSON")

    triage = sub.add_parser("triage", help="研判 JSONL 文件或单条告警")
    triage.add_argument("-f", "--file", type=Path, help="JSONL 文件，每行一条告警")
    triage.add_argument("--alert", type=str, help="单条告警的 JSON 字符串")
    triage.add_argument("--source", type=str, default=None, help="强制指定数据源")
    triage.add_argument("-o", "--out", type=Path, help="生成报告，后缀 .md 或 .html")
    triage.add_argument("--llm", action="store_true", help="启用 LLM 叙述层")
    triage.add_argument("--json", action="store_true", help="把结果以 JSON 打印到 stdout")
    triage.add_argument("-n", "--limit", type=int, default=10, help="终端展示条数")

    serve = sub.add_parser("serve", help="启动 HTTP 服务")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8000)
    serve.add_argument("--fastapi", action="store_true", help="用 FastAPI（需安装依赖）")
    serve.add_argument("--llm", action="store_true")

    rules = sub.add_parser("rules", help="规则管理")
    rules.add_argument("--lint", action="store_true", help="检查规则完整性")
    rules.add_argument("--json", action="store_true")

    ev = sub.add_parser("evaluate", help="在带标签的数据集上评估")
    ev.add_argument("--data", type=Path, default=Path("data/samples/labeled.jsonl"))
    ev.add_argument("--json", action="store_true")
    ev.add_argument("--write", type=Path, help="把评估结论写入 markdown 文件")
    ev.add_argument("--min-accuracy", type=float, default=None, help="低于该准确率则退出码 1（CI 回归门槛）")
    ev.add_argument("--min-f1", type=float, default=None, help="低于该 F1 则退出码 1")

    return parser


def _pipeline(args: argparse.Namespace) -> TriagePipeline:
    overrides: dict[str, Any] = {}
    if getattr(args, "llm", False):
        overrides["llm_enabled"] = True
    return TriagePipeline(load_settings(**overrides))


def _print_result(result, show_breakdown: bool = True) -> None:
    label = VERDICT_LABEL.get(result.verdict, result.verdict)
    bar = "█" * max(1, round(result.risk_score / 5)) + "·" * (20 - max(1, round(result.risk_score / 5)))
    print(f"\n  {label}  风险 {result.risk_score:>3}/100  [{bar}]")
    print(f"  攻击类型 : {result.attack_type}")
    print(f"  严重度   : {result.severity}    误报概率 {result.fp_probability:.0%}    置信度 {result.confidence:.0%}")
    print(f"  关联     : {result.incident.incident_id}（{result.incident.count} 次）"
          f"{'  [突发]' if result.incident and result.incident.burst else ''}")
    print(f"  检测器   : {', '.join(d.rule_id for d in result.detections) or '无命中'}")
    if result.mitre_techniques:
        print(f"  ATT&CK   : {', '.join(result.mitre_techniques)}")
    print(f"  叙述来源 : {result.narrative_source}{'（已降级）' if result.degraded else ''}")
    print(f"\n  {result.analysis}\n")
    print("  处置建议：")
    for idx, item in enumerate(result.recommendations, start=1):
        print(f"    {idx}. {item}")
    if show_breakdown:
        print("\n  分数构成：")
        for row in result.meta.get("score_breakdown", []):
            print(f"    {row['label']:<14} {row['detail'][:56]:<56} {row['delta']:+5}  → {row['total']}")
    print(f"\n  耗时 {result.elapsed_ms} ms\n")


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        if args.command == "demo":
            pipeline = _pipeline(args)
            result = pipeline.triage_raw(DEMO_ALERT)
            if args.json:
                print(json.dumps(result.to_dict(), ensure_ascii=False, indent=2))
            else:
                _print_result(result)
            return 0

        if args.command == "triage":
            pipeline = _pipeline(args)
            if args.alert:
                raws = [json.loads(args.alert)]
            elif args.file:
                raws = [
                    json.loads(line)
                    for line in args.file.read_text(encoding="utf-8").splitlines()
                    if line.strip()
                ]
            else:
                data = sys.stdin.read().strip()
                if not data:
                    print("需要 --file、--alert 或从 stdin 传入 JSON", file=sys.stderr)
                    return 2
                raws = json.loads(data)
                if isinstance(raws, dict):
                    raws = [raws]

            results, summary = pipeline.triage_batch(raws, args.source)
            if args.json:
                print(json.dumps(
                    {"results": [r.to_dict() for r in results], "summary": summary},
                    ensure_ascii=False,
                    indent=2,
                ))
            else:
                for result in sorted(results, key=lambda r: -r.risk_score)[: args.limit]:
                    _print_result(result, show_breakdown=False)
                print(f"共 {summary['total']} 条 | 自动定性 {summary['auto_triage_rate']:.0%} | "
                      f"p95 {summary['p95_ms']} ms")
                print(f"结论分布：{summary['verdicts']}")
            if args.out:
                path = write_report(results, summary, args.out)
                print(f"报告已写入 {path}")
            return 0

        if args.command == "serve":
            pipeline = _pipeline(args)
            if args.fastapi:
                try:
                    import uvicorn  # type: ignore
                except ImportError:
                    print("未安装 uvicorn，请先 pip install -r requirements-api.txt", file=sys.stderr)
                    return 2
                from .api.fastapi_app import create_app

                uvicorn.run(create_app(pipeline), host=args.host, port=args.port)
                return 0
            from .api.stdlib_server import run_server

            run_server(pipeline, host=args.host, port=args.port)
            return 0

        if args.command == "rules":
            rules = load_rules()
            problems = lint_rules(rules)
            if args.json:
                print(json.dumps(
                    {
                        "total": len(rules),
                        "rules": [
                            {"id": r.id, "title": r.title, "severity": r.severity, "mitre": r.mitre}
                            for r in rules
                        ],
                        "problems": problems,
                    },
                    ensure_ascii=False,
                    indent=2,
                ))
            else:
                print(f"已加载 {len(rules)} 条规则")
                for rule in rules:
                    print(f"  {rule.id:<18} {rule.severity:<9} {rule.title}  [{','.join(rule.mitre)}]")
                if args.lint:
                    if problems:
                        print("\n规则检查发现问题：")
                        for problem in problems:
                            print(f"  - {problem}")
                        return 1
                    print("\n规则检查通过（id 唯一 / MITRE 完整 / 有处置建议）")
            return 0

        if args.command == "evaluate":
            pipeline = _pipeline(args)
            samples = load_labeled(args.data)
            report = evaluate(pipeline, samples)
            if args.json:
                print(json.dumps(report.to_dict(), ensure_ascii=False, indent=2))
            else:
                print(render_eval_markdown(report))
            if args.write:
                args.write.parent.mkdir(parents=True, exist_ok=True)
                args.write.write_text(render_eval_markdown(report), encoding="utf-8")
                print(f"已写入 {args.write}")

            failed = False
            if args.min_accuracy is not None and report.accuracy < args.min_accuracy:
                print(
                    f"回归失败: 准确率 {report.accuracy:.2%} 低于门槛 {args.min_accuracy:.2%}",
                    file=sys.stderr,
                )
                failed = True
            if args.min_f1 is not None and report.f1 < args.min_f1:
                print(f"回归失败: F1 {report.f1:.2%} 低于门槛 {args.min_f1:.2%}", file=sys.stderr)
                failed = True
            return 1 if failed else 0

        parser.print_help()
        return 0
    except AlertsageError as exc:
        print(f"错误: {exc}", file=sys.stderr)
        return 1
    except FileNotFoundError as exc:
        print(f"文件不存在: {exc}", file=sys.stderr)
        return 1
