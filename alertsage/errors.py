"""异常层次。对外统一 AlertsageError，避免把内部实现细节漏给调用方。"""


class AlertsageError(Exception):
    """所有可预期错误的基类。"""


class ConfigError(AlertsageError):
    """配置非法，例如阈值越界、路径不存在。"""


class RuleError(AlertsageError):
    """规则文件格式错误。"""


class NormalizeError(AlertsageError):
    """原始告警无法归一化（缺关键字段/时间戳无法解析）。"""


class LLMError(AlertsageError):
    """LLM 调用失败。调用方应捕获并降级到本地模板叙述。"""
