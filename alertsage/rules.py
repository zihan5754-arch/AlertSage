"""声明式规则引擎。

为什么不用 if/elif 硬编码正则（也就是你 v0.1 的写法）：
1. 规则是数据不是代码，安全同学自己能加规则，不用改 Python；
2. 规则能单独 lint、能统计命中率、能按 ATT&CK 技术统计覆盖；
3. 每条规则带 MITRE 映射和建议动作，输出天然可解释。

规则格式（JSON，.yaml 需要本机装 PyYAML 才启用）：

    {
      "id": "WEB-SQLI-001",
      "title": "SQL 注入 - 布尔/联合永真式",
      "severity": "high",
      "category": "web",
      "confidence": 0.85,
      "mitre": ["T1190"],
      "match": {"all": [
          {"text": "regex:(?i)union\\\\s+select"},
          {"field": "target_url", "contains_any": ["/login", "/api"]}
      ]}
    }

条件 DSL：
  {"field": "...", "regex"|"contains"|"contains_any"|"equals"|"in"|
                        "startswith"|"endswith"|"gt"|"lt"|"exists": ...}
  {"all": [...]} / {"any": [...]} / {"not": {...}}
  {"text": "regex:..."}  # 对 Payload+URL+UA+原始日志的合并文本匹配
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from .errors import RuleError
from .models import SEVERITY_ORDER, Alert, Detection, Evidence

DEFAULT_RULES_DIR = Path(__file__).parent / "rules"

_OPERATORS = {
    "regex",
    "contains",
    "contains_any",
    "equals",
    "in",
    "startswith",
    "endswith",
    "gt",
    "lt",
    "exists",
}


@dataclass(slots=True)
class Rule:
    id: str
    title: str
    severity: str
    category: str
    match: dict[str, Any]
    confidence: float = 0.7
    mitre: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)
    description: str = ""
    enabled: bool = True
    # 规则自身可加/减权重，用于"高危但常见"的场景微调
    weight_delta: int = 0
    _compiled: dict[str, re.Pattern[str]] = field(default_factory=dict, repr=False)

    def compile(self) -> "Rule":
        """预编译正则，避免每条告警重复编译（性能上很关键）。"""
        self._compile_node(self.match)
        return self

    def _compile_node(self, node: dict[str, Any]) -> None:
        if not isinstance(node, dict):
            raise RuleError(f"规则 {self.id}: 条件必须是对象")
        if "text" in node:
            raw_text = str(node["text"])
            if _is_regex(raw_text):
                try:
                    re.compile(raw_text[len("regex:"):])
                except re.error as exc:
                    raise RuleError(f"规则 {self.id}: 正则非法 {raw_text!r} -> {exc}") from exc
        for key in ("all", "any"):
            if key in node:
                children = node[key]
                if not isinstance(children, list) or not children:
                    raise RuleError(f"规则 {self.id}: {key} 需要非空数组")
                for child in children:
                    self._compile_node(child)
        if "not" in node:
            self._compile_node(node["not"])
        for op, value in node.items():
            if op in ("all", "any", "not", "field", "text", "desc"):
                continue
            if op not in _OPERATORS:
                raise RuleError(f"规则 {self.id}: 不支持的操作符 {op}")
            if op == "regex":
                try:
                    pattern = re.compile(str(value))
                except re.error as exc:
                    raise RuleError(f"规则 {self.id}: 正则非法 {value!r} -> {exc}") from exc
                self._compiled[json.dumps(node, sort_keys=True)] = pattern

    # ---------------------------------------------------------- 匹配
    def matches(self, alert: Alert) -> tuple[bool, list[str]]:
        ok, reasons = _eval_node(self.match, self, alert)
        return ok, reasons


def _regex_for(rule: Rule, node: dict[str, Any]) -> re.Pattern[str]:
    key = json.dumps(node, sort_keys=True)
    pattern = rule._compiled.get(key)
    if pattern is None:  # compile() 未覆盖到的路径，兜底编译一次
        pattern = re.compile(str(node["regex"]))
        rule._compiled[key] = pattern
    return pattern


def _field_value(alert: Alert, name: str) -> Any:
    if name == "text":
        return alert.text()
    if name == "timestamp":
        return alert.timestamp
    value = getattr(alert, name, None)
    if value is None and name in alert.extra:
        value = alert.extra[name]
    return value


def _eval_node(node: dict[str, Any], rule: Rule, alert: Alert) -> tuple[bool, list[str]]:
    if "all" in node:
        details: list[str] = []
        for child in node["all"]:
            ok, why = _eval_node(child, rule, alert)
            if not ok:
                return False, []
            details.extend(why)
        return True, details

    if "any" in node:
        details = []
        for child in node["any"]:
            ok, why = _eval_node(child, rule, alert)
            if ok:
                details.extend(why)
                return True, details
        return False, []

    if "not" in node:
        ok, _ = _eval_node(node["not"], rule, alert)
        return (not ok), []

    # 叶子条件
    if "text" in node:
        raw_text = str(node["text"])
        pattern_str = raw_text[len("regex:"):] if _is_regex(raw_text) else re.escape(raw_text)
        leaf = {"field": "text", "regex": pattern_str}
    else:
        leaf = node

    field_name = str(leaf.get("field", "text"))
    value = _field_value(alert, field_name)
    text = "" if value is None else str(value)
    hits: list[str] = []

    for op, expected in leaf.items():
        if op == "field" or op == "desc":
            continue
        if op == "exists":
            present = value is not None and str(value) != ""
            if bool(expected) != present:
                return False, []
            hits.append(f"{field_name} {'存在' if present else '不存在'}")
            continue
        if value is None:
            return False, []
        if op == "regex":
            pattern = _regex_for(rule, leaf)
            m = pattern.search(text)
            if not m:
                return False, []
            hits.append(f"{field_name} 命中正则 {pattern.pattern}（片段 {m.group(0)[:80]!r}）")
        elif op == "contains":
            if str(expected).lower() not in text.lower():
                return False, []
            hits.append(f"{field_name} 包含 {expected!r}")
        elif op == "contains_any":
            lowered = text.lower()
            found = [str(x) for x in expected if str(x).lower() in lowered]
            if not found:
                return False, []
            hits.append(f"{field_name} 包含 {found!r}")
        elif op == "equals":
            if text.lower() != str(expected).lower():
                return False, []
            hits.append(f"{field_name} == {expected!r}")
        elif op == "in":
            if text.lower() not in {str(x).lower() for x in expected}:
                return False, []
            hits.append(f"{field_name} 属于 {expected!r}")
        elif op == "startswith":
            if not text.lower().startswith(str(expected).lower()):
                return False, []
            hits.append(f"{field_name} 以 {expected!r} 开头")
        elif op == "endswith":
            if not text.lower().endswith(str(expected).lower()):
                return False, []
            hits.append(f"{field_name} 以 {expected!r} 结尾")
        elif op in ("gt", "lt"):
            try:
                actual_num = float(value)
                expected_num = float(expected)
            except (TypeError, ValueError):
                return False, []
            if op == "gt" and not actual_num > expected_num:
                return False, []
            if op == "lt" and not actual_num < expected_num:
                return False, []
            hits.append(f"{field_name} {op} {expected_num}")
        else:
            raise RuleError(f"规则 {rule.id}: 未知操作符 {op}")
    return bool(hits), hits


def _is_regex(value: str) -> bool:
    return isinstance(value, str) and value.startswith("regex:")


# ---------------------------------------------------------------- 加载
def _load_file(path: Path) -> list[dict[str, Any]]:
    text = path.read_text(encoding="utf-8")
    if path.suffix in (".yaml", ".yml"):
        try:
            import yaml  # type: ignore
        except ImportError as exc:  # pragma: no cover - 取决于环境
            raise RuleError(f"{path.name}: 需要 PyYAML 才能读取 YAML 规则") from exc
        payload = yaml.safe_load(text)
    else:
        payload = json.loads(text)
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict) and isinstance(payload.get("rules"), list):
        return payload["rules"]
    raise RuleError(f"{path.name}: 规则文件必须是数组或 {{'rules': [...]}}")


def parse_rule(payload: dict[str, Any]) -> Rule:
    if not isinstance(payload, dict):
        raise RuleError(f"规则必须是对象，收到 {type(payload).__name__}")
    missing = [k for k in ("id", "title", "severity", "match") if not payload.get(k)]
    if missing:
        raise RuleError(f"规则缺少字段 {missing}: {payload.get('id', '<no id>')}")
    severity = str(payload["severity"]).lower()
    if severity not in SEVERITY_ORDER:
        raise RuleError(f"规则 {payload['id']}: severity 必须是 {SEVERITY_ORDER}")
    confidence = float(payload.get("confidence", 0.7))
    if not 0.0 < confidence <= 1.0:
        raise RuleError(f"规则 {payload['id']}: confidence 必须在 (0, 1]")
    mitre = payload.get("mitre") or []
    if not isinstance(mitre, list) or not all(isinstance(m, str) for m in mitre):
        raise RuleError(f"规则 {payload['id']}: mitre 必须是字符串数组")
    return Rule(
        id=str(payload["id"]),
        title=str(payload["title"]),
        severity=severity,
        category=str(payload.get("category", "generic")),
        match=payload["match"],
        confidence=confidence,
        mitre=[m.upper() for m in mitre],
        recommendations=[str(x) for x in payload.get("recommendations", [])],
        description=str(payload.get("description", "")),
        enabled=bool(payload.get("enabled", True)),
        weight_delta=int(payload.get("weight_delta", 0)),
    ).compile()


def load_rules(rules_dir: Path | str | None = None) -> list[Rule]:
    directory = Path(rules_dir) if rules_dir else DEFAULT_RULES_DIR
    if not directory.exists():
        raise RuleError(f"规则目录不存在: {directory}")
    files = sorted(
        p for p in directory.iterdir() if p.suffix in (".json", ".yaml", ".yml") and p.is_file()
    )
    if not files:
        raise RuleError(f"规则目录为空: {directory}")
    rules: list[Rule] = []
    seen: dict[str, str] = {}
    for path in files:
        for payload in _load_file(path):
            rule = parse_rule(payload)
            if rule.id in seen:
                raise RuleError(f"规则 id 重复: {rule.id}（{seen[rule.id]} 与 {path.name}）")
            seen[rule.id] = path.name
            rules.append(rule)
    return sorted(rules, key=lambda r: (-SEVERITY_ORDER.index(r.severity), r.id))


def lint_rules(rules: Iterable[Rule]) -> list[str]:
    """rules lint 用：返回告警文本，空列表代表干净。"""
    problems: list[str] = []
    seen: set[str] = set()
    for rule in rules:
        if rule.id in seen:
            problems.append(f"{rule.id}: id 重复")
        seen.add(rule.id)
        if not rule.mitre:
            problems.append(f"{rule.id}: 缺少 MITRE 映射")
        if not rule.recommendations:
            problems.append(f"{rule.id}: 缺少处置建议")
        if not rule.description:
            problems.append(f"{rule.id}: 缺少 description")
    return problems


def rule_to_detection(rule: Rule, reasons: list[str]) -> Detection:
    evidence = [
        Evidence(
            kind="rule",
            code=rule.id,
            detail=reason,
            weight=0,
            mitre=rule.mitre,
        )
        for reason in reasons
    ]
    return Detection(
        rule_id=rule.id,
        title=rule.title,
        severity=rule.severity,
        category=rule.category,
        confidence=rule.confidence,
        mitre=list(rule.mitre),
        evidence=evidence,
        recommendations=list(rule.recommendations),
    )
