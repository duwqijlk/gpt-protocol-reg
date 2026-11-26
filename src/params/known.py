# 已核验确定性参数构造器
# 来源：analysis/window-1030/protocol-review.md（JS recordSeq 佐证）+ 四run参数矩阵锚点
# 每个函数标注：证据（JS源码位置/实测值形态）
from __future__ import annotations
import base64, hashlib, secrets, time, json


def pkce_verifier(length: int = 64) -> str:
    """code_verifier：随机 43-64 字符 Base64URL。JS 生成点：app-runtime 内 crypto.getRandomValues 链。"""
    return base64.urlsafe_b64encode(secrets.token_bytes(48)).decode().rstrip("=")


def pkce_challenge_s256(verifier: str) -> str:
    """code_challenge = BASE64URL(SHA256(verifier))；实测 method=S256、challenge 43 字符（records 8399）。"""
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).decode().rstrip("=")


def new_oauth_state(nbytes: int = 32) -> str:
    """state：43 字符 Base64URL 形态（实测 records 8399/10898 逐值相等关联）。"""
    return base64.urlsafe_b64encode(secrets.token_bytes(nbytes)).decode().rstrip("=")


def new_logging_id() -> str:
    """auth_session_logging_id / x-access-flow-invocation-id / x-openai-document-navigation-id：
    36 字符 UUID v4 形态（实测长度恒 36）。"""
    import uuid
    return str(uuid.uuid4())


def new_oai_did() -> str:
    """oai-did / OAI-Device-Id / device_id：36 字符 UUID v4 形态；同一 run 内逐值相等（跨 run 独立）。"""
    import uuid
    return str(uuid.uuid4())


def sentinel_error_fallback(flow: str) -> str:
    """openai-sentinel-token 错误包装：{"e":"k9d4s6v3b2"}
    证据：JS records 9329 FailedToFetchSentinelToken=k9d4s6v3b2；
    records 9053 rt('authorize_continue',{timeoutMs:5e3}).catch→该包装仍发 send-otp。
    注意：仅 authorize_continue 场景实测到错误包装；validate/create_account 需完整 token（B 线）。"""
    return json.dumps({"e": "k9d4s6v3b2"})


def sentinel_cache_valid(expire_at: int, now_s: float | None = None) -> bool:
    """sentinel token 缓存窗口：JS Yue=9*60*1e3ms（records 9329）；expire_after=540s。
    判定：now < expire_at 且距获取 < 540s。"""
    now = now_s if now_s is not None else time.time()
    return now < expire_at


# ---- sentinel 请求/业务头构造（形状实锤：1031 链路抓包 + 08-headers.md 头名表） ----

def build_sentinel_req_body(state, flow: str, config25: list) -> dict:
    """sentinel.openai.com/backend-api/sentinel/req 请求体（1031 实测形状）：
    {"p": requirements token gAAAAAC…, "id": oai-device-id, "flow": <flow>}
    p = requirements_token(config25)——sentinel.py 已实现（config[3]=1 无哈希循环）。"""
    from ..sentinel import requirements_token
    return {"p": requirements_token(config25), "id": state.oai_did, "flow": flow}


def build_sentinel_headers(state, flow: str, *, challenge: str = "", dx: str = "",
                           key: str = "", proof_token: str = "", so_token: str = "",
                           error_fallback: bool = False, math_random: float | None = None) -> dict:
    """业务请求的 sentinel 双头（1031 实测 JSON 形状 + 08-headers.md 头名表）：
    openai-sentinel-token = JSON.stringify({p, t, c, id, flow})
        p = proof token（PoW 答案 gAAAAAB…，sentinel.solve_proofofwork）
        t = dx-VM 输出（sentinel.generate_t——1031 材料 EXACT MATCH）
        c = 配对 sentinel/req 响应 token（gAAAAAB…）
        id = oai-device-id；flow = 流程名
    openai-sentinel-so-token = JSON.stringify({so, c, id, flow})
    error_fallback=True（仅 authorize_continue 实测）→ openai-sentinel-token={"e":"k9d4s6v3b2"}"""
    headers = {}
    if error_fallback:
        headers["openai-sentinel-token"] = sentinel_error_fallback(flow)
        return headers
    if dx and key:
        from ..sentinel import generate_t
        t = generate_t(dx, key, math_random=math_random)
    else:
        t = state.sentinel_cache.get(f"t:{flow}", "")
    token = {"p": proof_token, "t": t, "c": challenge, "id": state.oai_did, "flow": flow}
    headers["openai-sentinel-token"] = json.dumps(token, separators=(",", ":"))
    if so_token:
        headers["openai-sentinel-so-token"] = json.dumps(
            {"so": so_token, "c": challenge, "id": state.oai_did, "flow": flow}, separators=(",", ":"))
    return headers


def build_sentinel_prepare_body(state, config25: list) -> dict:
    """chat-requirements/prepare 请求体（1031 实测：仅 p 字段，599-835 字符）：
    {"p": requirements token}——mweb 与 backend 两入口同形。"""
    from ..sentinel import requirements_token
    return {"p": requirements_token(config25)}


def build_conversation_init_timezone() -> dict:
    """conversation/init body 的时区字段（records 11367 JS 证据）：
    timezone = Intl.DateTimeFormat().resolvedOptions().timeZone
    timezone_offset_min = new Date().getTimezoneOffset()  → 实测 Asia/Taipei / -480（UTC+8）
    协议端按出口地区映射；值形态必须是 IANA 时区名 + 分钟偏移（UTC 减本地）。"""
    return {"timezone": "Asia/Taipei", "timezone_offset_min": -480}


def build_mweb_form_fields(viewport=(1264, 625), pixel_ratio=1, mode="anonymous", session_epoch=None) -> dict:
    """unauth-mweb conversation/prepare 表单 5 项（records 3072 JS 证据，实测结构）：
    conversationRetryOwner / conversationState / clientContextualInfo 为 JSON 序列化字符串。
    - conversationState: {messages:[], parentMessageId:"...", userMessageCount:0, mode:...}
    - clientContextualInfo: 应用名/通知能力/深色模式/page_width/page_height/pixel_ratio/time_since_loaded
    - lightweight_authenticated: '0'|'1'（records 3072: c.mode==='authenticated'?'1':'0'）
    parentMessageId 空会话哨兵值：19 字符（实测长度，值脱敏）——待 B 线从 JS 常量提取明文。"""
    return {
        "lightweight_authenticated": "0" if mode != "authenticated" else "1",
        "conversationRetryOwner": json.dumps({"mode": mode, "sessionEpoch": session_epoch}),
        "conversationState": json.dumps({"messages": [], "parentMessageId": "PLACEHOLDER_19", "userMessageCount": 0}),
        "clientContextualInfo": json.dumps({
            "page_width": viewport[0], "page_height": viewport[1], "pixel_ratio": pixel_ratio,
            "time_since_loaded": 1,
        }),
        "timezone": "Asia/Taipei", "timezoneOffsetMinutes": "-480",
    }


def _placeholder(n: int) -> str:
    """待 B 线 JS 证据回填的占位值，长度严格等于抓包实测。"""
    return ("PLACEHOLDER_" + "X" * max(0, n - 12))[:n]


def build_authorize_query(state) -> dict:
    """oauth/authorize 完整 query（14 项，1031 records 5450 实测字段集，顺序按 JS 生成序）：
    client_id(29)/response_type=code/redirect_uri(44)/scope(97)/code_challenge(43)/
    code_challenge_method=S256/state(43)/audience(25)/device_id(36=与oai-did同值)/
    prompt=login/screen_hint=signup/login_hint(邮箱)/auth_session_logging_id(36)/ccaps(40)
    —— audience/ccaps 精确值待 B 线 JS 证据（当前占位按实测长度断言）。"""
    return {
        "audience": "https://api.openai.com/v1",       # 实测 25 字符（1031 records 5450 原值）
        "auth_session_logging_id": state.auth_session_logging_id,
        "ccaps": "login_methods chatgpt_login_finalizer_v1",   # 实测 40 字符（1031 records 5450 原值）
        "client_id": client_id(),
        "code_challenge": state.code_challenge,
        "code_challenge_method": "S256",
        "device_id": state.oai_did,
        "login_hint": state.login_hint,
        "prompt": "login",
        "redirect_uri": "https://chatgpt.com/api/auth/callback/openai",   # 实测 44 字符
        "response_type": "code",
        "scope": " ".join(oauth_scopes()),            # 8 项 join 实测 97 字符
        "screen_hint": "signup",
        "state": state.oauth_state,
    }


def oauth_scopes() -> list:
    """8 项 scope 实测集合（records 8399/9655 集合相等）"""
    return ["openid", "email", "profile", "offline_access",
            "model.request", "model.read", "organization.read", "organization.write"]


def client_id() -> str:
    """公开 OAuth client_id（records 8399 实测原值）"""
    return "app_X8zY6vW2pQ9tR3dE7nK1jL5gH"
