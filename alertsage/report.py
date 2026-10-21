"""报告渲染：Markdown 给人看/贴群，HTML 当交付物截图。

刻意不引入 Jinja2：模板就是字符串拼接 + html.escape，
少一个依赖，也避免"为了一个表格装一整套模板引擎"。
"""

from __future__ import annotations

import html
from pathlib import Path
from typing import Any

from .models import TriageResult

_VERDICT_LABEL = {
    "true_positive": "真实攻击",
    "false_positive": "疑似误报",
    "needs_review": "待人工复核",
}

_VERDICT_COLOR = {
    "true_positive": "#c0392b",
    "false_positive": "#7f8c8d",
    "needs_review": "#d68910",
}


def _sorted(results: list[TriageResult]) -> list[TriageResult]:
    return sorted(results, key=lambda r: (-r.risk_score, r.alert_id))


# ---------------------------------------------------------------- Markdown
def render_markdown(results: list[TriageResult], summary: dict[str, Any], top: int = 10) -> str:
    ordered = _sorted(results)
    lines: list[str] = [
        "# AlertSage 研判报告",
        "",
        f"- 告警总数：**{summary.get('total', len(results))}**",
        f"- 自动定性率：**{summary.get('auto_triage_rate', 0):.1%}**"
        f"（待人工复核 {summary.get('needs_review_rate', 0):.1%}）",
        f"- 平均风险分：**{summary.get('avg_risk', 0)}**",
        f"- 处理耗时：p50 {summary.get('p50_ms', 0)} ms / p95 {summary.get('p95_ms', 0)} ms",
        "",
        "## 结论分布",
        "",
        "| 结论 | 数量 |",
        "| --- | ---: |",
    ]
    for verdict, count in (summary.get("verdicts") or {}).items():
        lines.append(f"| {_VERDICT_LABEL.get(verdict, verdict)} | {count} |")

    lines += ["", "## 风险最高的告警", "", "| # | 结论 | 风险 | 攻击类型 | 来源 | 命中规则 |", "| ---: | --- | ---: | --- | --- | --- |"]
    for index, result in enumerate(ordered[:top], start=1):
        lines.append(
            "| {i} | {verdict} | {risk} | {title} | {src} | {rules} |".format(
                i=index,
                verdict=_VERDICT_LABEL.get(result.verdict, result.verdict),
                risk=result.risk_score,
                title=_md(result.attack_type),
                src=result.meta.get("src_scope", "-"),
                rules=", ".join(d.rule_id for d in result.detections[:3]) or "-",
            )
        )

    if ordered:
        top_result = ordered[0]
        lines += ["", "## 证据链示例", "", f"告警 `{top_result.alert_id}`：", ""]
        for item in top_result.evidence:
            lines.append(f"- `{item.kind}` {item.detail}（{item.weight:+d}）")
        lines += ["", "### 分数构成", "", "| 环节 | 说明 | 增量 | 累计 |", "| --- | --- | ---: | ---: |"]
        for row in top_result.meta.get("score_breakdown", []):
            lines.append(f"| {row['label']} | {row['detail']} | {row['delta']:+} | {row['total']} |")

    if summary.get("errors"):
        lines += ["", "## 解析失败", ""]
        for err in summary["errors"]:
            lines.append(f"- 第 {err['index']} 条：{err['error']}")

    lines += ["", "---", "", "由 AlertSage 自动生成，结论需人工复核后再对外。"]
    return "\n".join(lines) + "\n"


def _md(text: str) -> str:
    return str(text).replace("|", "\\|")


# ---------------------------------------------------------------- HTML
def render_html(results: list[TriageResult], summary: dict[str, Any], top: int = 20) -> str:
    ordered = _sorted(results)
    rows = []
    for index, result in enumerate(ordered[:top], start=1):
        color = _VERDICT_COLOR.get(result.verdict, "#333")
        rules = ", ".join(d.rule_id for d in result.detections[:3]) or "-"
        rows.append(
            "<tr>"
            f"<td>{index}</td>"
            f'<td style="color:{color};font-weight:600">{html.escape(_VERDICT_LABEL.get(result.verdict, result.verdict))}</td>'
            f"<td>{result.risk_score}</td>"
            f"<td>{result.fp_probability:.0%}</td>"
            f"<td>{html.escape(result.severity)}</td>"
            f"<td>{html.escape(result.attack_type)}</td>"
            f"<td>{html.escape(rules)}</td>"
            "</tr>"
        )

    detail_html = ""
    if ordered:
        top_result = ordered[0]
        items = "".join(
            f"<li><code>{html.escape(e.kind)}</code> {html.escape(e.detail)} "
            f"<b>({e.weight:+d})</b></li>"
            for e in top_result.evidence
        )
        detail_html = f"""
        <h2>证据链示例 · {html.escape(top_result.alert_id)}</h2>
        <p class="analysis">{html.escape(top_result.analysis)}</p>
        <ul class="evidence">{items}</ul>"""

    verdict_rows = "".join(
        f"<tr><td>{html.escape(_VERDICT_LABEL.get(k, k))}</td><td>{v}</td></tr>"
        for k, v in (summary.get("verdicts") or {}).items()
    )

    return f"""<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<title>AlertSage 研判报告</title>
<style>
  :root {{ color-scheme: light; }}
  body {{ font-family: -apple-system, "Segoe UI", "Microsoft YaHei", sans-serif;
         margin: 0; padding: 32px; background: #f6f7f9; color: #1f2328; }}
  h1 {{ margin: 0 0 8px; font-size: 26px; }}
  .meta {{ color: #656d76; margin-bottom: 24px; }}
  .cards {{ display: flex; gap: 16px; margin-bottom: 24px; flex-wrap: wrap; }}
  .card {{ background: #fff; border: 1px solid #d8dee4; border-radius: 10px;
           padding: 16px 20px; min-width: 160px; }}
  .card .k {{ font-size: 12px; color: #656d76; }}
  .card .v {{ font-size: 24px; font-weight: 700; margin-top: 4px; }}
  table {{ border-collapse: collapse; width: 100%; background: #fff;
           border: 1px solid #d8dee4; border-radius: 10px; overflow: hidden; }}
  th, td {{ padding: 9px 12px; border-bottom: 1px solid #eaeef2; font-size: 13px; text-align: left; }}
  th {{ background: #f6f8fa; font-weight: 600; }}
  .analysis {{ background: #fff; border-left: 4px solid #0969da; padding: 12px 16px;
               margin: 8px 0 16px; line-height: 1.7; }}
  .evidence {{ background: #fff; border: 1px solid #d8dee4; border-radius: 10px;
               padding: 12px 16px 12px 32px; line-height: 1.8; font-size: 13px; }}
  footer {{ margin-top: 24px; color: #656d76; font-size: 12px; }}
</style>
</head>
<body>
  <h1>AlertSage 研判报告</h1>
  <div class="meta">共 {summary.get("total", len(results))} 条告警 · 自动定性率
    {summary.get("auto_triage_rate", 0):.1%} · p95 {summary.get("p95_ms", 0)} ms</div>
  <div class="cards">
    <div class="card"><div class="k">真实攻击</div><div class="v">{(summary.get("verdicts") or {}).get("true_positive", 0)}</div></div>
    <div class="card"><div class="k">疑似误报</div><div class="v">{(summary.get("verdicts") or {}).get("false_positive", 0)}</div></div>
    <div class="card"><div class="k">待复核</div><div class="v">{(summary.get("verdicts") or {}).get("needs_review", 0)}</div></div>
    <div class="card"><div class="k">平均风险分</div><div class="v">{summary.get("avg_risk", 0)}</div></div>
  </div>
  <h2>处置优先级 Top {min(top, len(ordered))}</h2>
  <table>
    <thead><tr><th>#</th><th>结论</th><th>风险</th><th>误报概率</th><th>严重度</th><th>攻击类型</th><th>命中规则</th></tr></thead>
    <tbody>{"".join(rows) or '<tr><td colspan="7">没有数据</td></tr>'}</tbody>
  </table>
  {detail_html}
  <footer>由 AlertSage 自动生成，结论需人工复核后再对外。结论分布：{"、".join(f"{_VERDICT_LABEL.get(k, k)} {v}" for k, v in (summary.get('verdicts') or {}).items())}。</footer>
</body>
</html>
"""


def write_report(
    results: list[TriageResult], summary: dict[str, Any], out_path: Path | str
) -> Path:
    path = Path(out_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    content = render_html(results, summary) if path.suffix.lower() == ".html" else render_markdown(
        results, summary
    )
    path.write_text(content, encoding="utf-8")
    return path
