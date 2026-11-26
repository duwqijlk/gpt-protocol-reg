# 实测字段形态断言（来自 analysis/window-1031/fields-sentinel.md 等，104 行证据）
# 用途：verify/ 阶段对构造器输出的形态断言；数值区间来自实际抓包，超出即误。
from __future__ import annotations


# ---- sentinel/req 响应（登录态与 noauth 同构） ----
RESPONSE_FORM = {
    "token": {"length_range": (2892, 3000), "prefix": "gAAAAAB"},      # 88785c7fdfb6/f377c906156e
    "persona": {"length": 19},                                          # chatgpt-noauth 族
    "expire_after": {"value": 540},
    "expire_at": {"unit": "unix_seconds"},
}

# ---- finalize 请求体（登录态 chat-requirements）实测长度 ----
FINALIZE_BODY_FORM = {
    "prepare_token": (3704, 4088),     # 08bb04f9c471 / e9131d8ea7a5
    "proofofwork":   (729, 781),       # 913cabde3041 / ae3001ab0636
    "turnstile":     (1796, 2108),     # 2b30fb0f4405 / 9b5a052d107d —— 求解后 token，非 dx
}

# ---- 登录态公共头（hook 可见，1031 实测） ----
LOGIN_HEADERS_FORM = {
    "authorization": {"prefix": "Bearer ", "length_range": (1950, 1980)},   # JWT 1967
    "chatgpt-account-id": {"length": 36},                                    # UUID v4 形态
    "oai-device-id": {"length": 36},        # 与 oai-did 同值（10240）
    "oai-did": {"length": 36},
    "oai-language": {"length": 5},          # 区域相关：IN 实测 hi-IN
    "originator": {"length": 13},
    "x-openai-codex-window-type": {"length": 7},
    "x-openai-web-frontend": {"length": 13},
    "x-openai-rate-limit-join-workspace": {"length": 1},
    "x-openai-rejoin-pro-cta": {"length": 1},
}

# ---- cookie 全生命周期（1031 实测，sentinel 响应 set-cookie 属性齐全） ----
COOKIE_FORM = {
    "__cf_bm": {"length_range": (198, 199), "attrs": ["secure", "httponly", "samesite", "partitioned"]},
    "__cflb": {"length_range": (42, 43)},
    "_cfuvid": {"length": 113},
    "cf_clearance": {"length": 308},
    "__oailb": {"length": 317},
    "oai-did": {"length": 36},
    "oai-did-first-seen": {"length": 50},
    "oai-client-session-epoch": {"length": 36},
    "oaicom-stable-id": {"length": 36},
    "oai-sc": {"length": 248},
    "_account": {"length": 8},
    "_account_is_fedramp": {"value": "false"},
    "_uasid": {"length": 478},
    "_umsid": {"length": 334},
    "__obi": {"length": 22},
    "__Host-next-auth.csrf-token": {"length": 131},
    "__Secure-next-auth.callback-url": {"length": 28},
    "__Secure-next-auth.session-token.0": {"length": 3933},
    "__Secure-next-auth.session-token.1": {"length": 167},
    "oai-mweb-auth-pending": {"length": 82},
    "oai-hlib": {"value": "true"},
    "g_state": {"length": 140},
    "_dd_s_v2": {"length": 127},
}

# ---- hook↔CDP 配对口径（hook-association.json 实测） ----
PAIRING = {"method": "session+url+time", "observed_delta_ms": (1, 14)}


def assert_form(field: str, value: str, form: dict) -> bool:
    """按形态断言；返回 True=通过，False=偏差（verify 用）"""
    v = value or ""
    if "prefix" in form and not v.startswith(form["prefix"]):
        return False
    if "length" in form and len(v) != form["length"]:
        return False
    if "length_range" in form and not (form["length_range"][0] <= len(v) <= form["length_range"][1]):
        return False
    return True
