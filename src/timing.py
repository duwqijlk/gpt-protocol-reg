# 请求节奏模型——数据源 analysis/protocol/ordering.json（四区域 gapStats）
# 协议端按此分布采样间隔，模拟人工节奏；敏感场景（validate/create）用人工区间，机械场景用实测区间。
from __future__ import annotations
import json, pathlib, random
from dataclasses import dataclass


@dataclass(frozen=True)
class GapRule:
    step: str
    median_ms: int
    min_ms: int
    max_ms: int
    human: bool = False     # human=True：需要人工节奏（收码/填表）


DEFAULT_RULES: dict[str, GapRule] = {
    "jsd-oneshot":                 GapRule("jsd-oneshot", 600, 376, 1000),
    "jsd-script":                  GapRule("jsd-script", 712, 9, 8005),
    "sentinel-sdk":                GapRule("sentinel-sdk", 667, 394, 1738),
    "sentinel-req":                GapRule("sentinel-req", 1664, 85, 5004),
    "oauth-authorize":             GapRule("oauth-authorize", 674, 329, 1151),
    "passwordless-send-otp":       GapRule("passwordless-send-otp", 596, 163, 1176),
    "email-otp-validate":          GapRule("email-otp-validate", 4072, 3499, 10328, human=True),
    "create-account":              GapRule("create-account", 5375, 3262, 6170, human=True),
    "auth-callback":               GapRule("auth-callback", 3942, 396, 4916),
    "chat-requirements-prepare":   GapRule("chat-requirements-prepare", 4679, 90, 108007),
    "chat-requirements-finalize":  GapRule("chat-requirements-finalize", 747, 153, 1431),
    "conversation-init":           GapRule("conversation-init", 832, 547, 2380),
    "bazaar-sync-token":           GapRule("bazaar-sync-token", 197, 4, 588),
    "bzr-sync":                    GapRule("bzr-sync", 608, 21, 1336),
    "unauth-conversation-prepare": GapRule("unauth-conversation-prepare", 0, 0, 1),
    "unauth-handoff":              GapRule("unauth-handoff", 14187, 396, 35527),
}


def load_rules(ordering_json: str | None = None) -> dict[str, GapRule]:
    """优先加载实测 ordering.json（四区域中位数），缺失项回退 DEFAULT_RULES。
    加载实测值时保留 DEFAULT_RULES 的 human 标记（人工节奏步骤不丢）。"""
    rules = dict(DEFAULT_RULES)
    if ordering_json and pathlib.Path(ordering_json).exists():
        data = json.loads(pathlib.Path(ordering_json).read_text(encoding="utf8"))
        for name, g in data.get("gapStats", {}).items():
            human = rules[name].human if name in rules else False
            rules[name] = GapRule(name, int(g["medianMs"]), int(g["minMs"]), int(g["maxMs"]), human)
    return rules


def sample_gap(rule: GapRule) -> float:
    """按实测 min/median/max 三点采样（线性插值简单模型，人工步骤可外注入真实等待）。"""
    if rule.median_ms <= rule.min_ms:
        return float(rule.min_ms)
    pick = random.random()
    if pick < 0.5:
        t = random.random()
        ms = rule.min_ms + (rule.median_ms - rule.min_ms) * t
    else:
        t = random.random()
        ms = rule.median_ms + (rule.max_ms - rule.median_ms) * t
    return ms / 1000.0
