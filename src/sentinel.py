# Sentinel 材料解析与求解器骨架
# 响应字段依据（1030 protocol-review 已核验，四 run 一致）：
#   persona / token(gAAAAAB…) / expire_after=540 / expire_at(Unix秒)
#   turnstile{required,dx} / proofofwork{required,seed,difficulty} / so{required,collector_dx,snapshot_dx}
# 请求体：{p,id,flow}；业务头 token：{p,t,c,id,flow} 与 {so,c,id,flow}（c=上游响应 token 实测相等）
from __future__ import annotations
import json, time
from dataclasses import dataclass, field


@dataclass
class SentinelChallenge:
    persona: str = ""
    token: str = ""
    expire_after: int = 0
    expire_at: int = 0
    turnstile_required: bool = False
    turnstile_dx: str = ""
    pow_required: bool = False
    pow_seed: str = ""
    pow_difficulty: str = ""
    so_required: bool = False
    so_collector_dx: str = ""
    so_snapshot_dx: str = ""
    raw: dict = field(default_factory=dict)

    @property
    def valid(self) -> bool:
        return bool(self.token) and time.time() < self.expire_at


def parse_sentinel_response(resp) -> SentinelChallenge:
    """从 sentinel/req（或 chat-requirements/prepare）响应解出挑战材料。
    resp: HttpResponse（body 为 JSON 文本）——字段名以 A 线矩阵核对为准。"""
    body = resp.body.decode() if isinstance(resp.body, bytes) else resp.body
    data = json.loads(body)
    ch = SentinelChallenge(
        persona=data.get("persona", ""), token=data.get("token", ""),
        expire_after=data.get("expire_after", 0), expire_at=data.get("expire_at", 0),
        raw=data)
    ts = data.get("turnstile") or {}
    ch.turnstile_required = bool(ts.get("required"))
    ch.turnstile_dx = ts.get("dx", "")
    pw = data.get("proofofwork") or {}
    ch.pow_required = bool(pw.get("required"))
    ch.pow_seed = pw.get("seed", "")
    ch.pow_difficulty = pw.get("difficulty", "")
    so = data.get("so") or {}
    ch.so_required = bool(so.get("required"))
    ch.so_collector_dx = so.get("collector_dx", "")
    ch.so_snapshot_dx = so.get("snapshot_dx", "")
    return ch


# ---- PoW 求解（算法证据：analysis/protocol/js-algorithms/01-proofofwork.md，三份独立实现交叉印证） ----

_M = 0xFFFFFFFF


def fnv1a32_fmix(s: str) -> str:
    """FNV-1a32 + murmur3-fmix32 终结雪崩 → 8 位十六进制（JS Math.imul 语义逐位对齐）。"""
    t = 0x811C9DC5
    for ch in s:
        t = (t ^ ord(ch)) & _M
        t = (t * 0x01000193) & _M
    t ^= t >> 16
    t = (t * 0x85EBCA6B) & _M
    t ^= t >> 13
    t = (t * 0xC2B2AE35) & _M
    t ^= t >> 16
    return format(t & _M, "08x")


def solve_proofofwork(seed: str, difficulty: str, config: list) -> str:
    """sentinel proof token：payload=base64(JSON(config))，找 i 使
    fnv1a32_fmix(seed+payload) 的 difficulty 长度前缀 <= difficulty（hex 字符串比较）。
    命中 → "gAAAAAB" + payload + "~S"；5e5 次未出解 → errorPrefix + base64(JSON("e"))。
    config[3]=尝试序号、config[9]=耗时（参照 JS 循环覆写）。"""
    import base64
    n = len(difficulty)
    for i in range(500_000):
        config[3] = i
        payload = base64.b64encode(
            json.dumps(config, separators=(",", ":"), ensure_ascii=False).encode()
        ).decode()
        h = fnv1a32_fmix(seed + payload)
        if h[:n] <= difficulty:
            return "gAAAAAB" + payload + "~S"
    err = base64.b64encode(json.dumps("e").encode()).decode()
    return "wQ8Lk5FbGpA2NcR9dShT6gYjU7VxZ4D" + err


def requirements_token(config: list) -> str:
    """sentinel/req 与 prepare 的 body.p："gAAAAAC" + base64(JSON(config25)) + "~S"。
    config[3]=1、config[9]=耗时，不跑哈希循环（desk-vm-slice.js 163-171 行证据）。
    "~S" 后缀实锤：1031 sentinel-req p 617 字符尾部 ~S（全链验证时发现）。"""
    import base64
    config[3] = 1
    payload = base64.b64encode(
        json.dumps(config, separators=(",", ":"), ensure_ascii=False).encode()
    ).decode()
    return "gAAAAAC" + payload + "~S"


def _selftest_pow() -> bool:
    """本地形态验证：求解命中前缀、token 结构、requirements token 结构。"""
    seed = "0.6318276523942984"
    difficulty = "0a2b3c"
    cfg = ["25601440", "Fri Nov 17 2026", None, 0, "UA-STRING", "s", "c/123/_", "en-US",
           "en-US,en", 0, "k−v", "doc", "win", 123.45, "sid-uuid", "names", 8, 1.7e12,
           0, 0, 0, 0, 0, 0, 0]
    tok = solve_proofofwork(seed, difficulty, list(cfg))
    assert tok.startswith("gAAAAAB") and tok.endswith("~S"), tok[:60]
    payload = tok[7:-2]
    import base64
    h = fnv1a32_fmix(seed + payload)
    assert h[:len(difficulty)] <= difficulty
    req = requirements_token(list(cfg))
    assert req.startswith("gAAAAAC")
    import base64 as b
    b.b64decode(req[7:] + "==")
    return True


def generate_so(collector_dx: str, snapshot_dx: str, key: str, *, region: str = "US",
                page_url: str = "", metrics: dict | None = None,
                math_random: float | None = None,
                events: bool | dict = False) -> str:
    """so-token 生成（collector_dx → 共享寄存器 → snapshot_dx，无重置续跑）。
    已验证：1031 auth 流真实 collector/snapshot 对 + reqP key → 静态核心与真实 so 逐字节相同
    （差异仅真实会话事件流段，见 js-algorithms/09-so-format.md）。
    events=True → 注入内置人形事件序列（24 点减速鼠标轨迹+点击+键盘+滚轮，
    经 collector 真实注册的 handler 落进寄存器并编码进 so：608→636 字符实测+28 事件段）。"""
    import subprocess, os, tempfile, json as _json
    here = os.path.dirname(os.path.abspath(__file__))
    node = os.environ.get("DSH_NODE") or os.path.expandvars(
        r"%USERPROFILE%\.dsh\dsh-runtimes\dsh-primary-runtime\dependencies\node\bin\node.exe")
    job = {"collector_dx": collector_dx, "snapshot_dx": snapshot_dx, "key": key}
    if page_url:
        job["pageUrl"] = page_url
    if metrics:
        job["metrics"] = metrics
    if math_random is not None:
        job["mathRandom"] = math_random
    if events:
        if isinstance(events, dict):
            job["events"] = events
        elif events in ("history", "history-otp", "history-form"):
            # 只注槽位历史（页面仪表语义），不派发 collector 事件——对齐真实抓包形态
            # （真实 so = collector 空态 Cx 标记 + 槽位历史；dispatch 模式会翻转标记 Cx→@N）
            # 场景（1034 真实行为档案）：otp=validate 页纯鼠标零键盘（数字键被过滤）；
            # form=create/about-you 页含 1-3 打字键
            scen = "form" if events == "history-form" else "otp"
            job["events"] = {"human": True, "mode": "history", "scenario": scen}
        else:
            job["events"] = {"human": True, "mode": "dispatch"}
    jf = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8")
    _json.dump(job, jf)
    jf.close()
    runner = (f'const sd = require({os.path.join(here, "sentinel_dx.js").replace(chr(92), "/")!r});'
              f'const job = require({jf.name.replace(chr(92), "/")!r});'
              f'if (job.events && job.events.human) job.events = Object.assign(sd.makeHumanEvents(Math.random, job.events.scenario), {{ mode: job.events.mode }});'
              f'sd.generateSo(job).then((s) => console.log(s)).catch((e) => {{ console.error("ERR", e.message); process.exit(1); }});')
    rf = tempfile.NamedTemporaryFile("w", suffix=".js", delete=False, encoding="utf-8")
    rf.write(runner)
    rf.close()
    try:
        r = subprocess.run([node, rf.name], capture_output=True, text=True, encoding="utf-8",
                           timeout=300, cwd=here)
        so = (r.stdout or "").strip()
        if r.returncode != 0 or len(so) < 8:
            raise RuntimeError(f"generate_so 失败: so_len={len(so)} stderr={(r.stderr or '')[:200]}")
        return so
    finally:
        for f in (jf.name, rf.name):
            try:
                os.unlink(f)
            except OSError:
                pass


def solve_turnstile(dx: str, key: str, **kw) -> str:
    """Turnstile dx 消费（已定案：sentinel 页内三级 VM，无 Cloudflare 组件）——即 t 生成。
    实装：generate_t（Node 端逐字客户端 VM + 校准桩，1031 材料逐字节验证）。"""
    return generate_t(dx, key, **kw)


def generate_t(dx: str, key: str, *, region: str = "US", page_url: str = "",
               metrics: dict | None = None, math_random: float | None = None,
               user_agent: str = "") -> str:
    """生产 t 生成器：调 Node 端 build/sentinel_dx.js（逐字客户端 VM + 校准桩）。
    已验证：1031 真实材料 EXACT MATCH（1388 字符逐字节、16 槽 0 差异）。
    参数：dx=sentinel/req 响应体 dx；key=配对 sentinel/req 请求体 p（gAAAAAC…）；
    region=IN/US/ID/JP 预置（语言与 config25/OAI-Language 同源）；page_url=当前页 URL；
    user_agent=与 HTTP 头同值的 UA（t 载荷内 navigator.userAgent 与线上请求头一致性）；
    math_random=校准回放（生产留 None 走真随机）。"""
    import subprocess, sys, os, json, tempfile
    here = os.path.dirname(os.path.abspath(__file__))
    node = os.environ.get("DSH_NODE") or os.path.expandvars(
        r"%USERPROFILE%\.dsh\dsh-runtimes\dsh-primary-runtime\dependencies\node\bin\node.exe")
    job = {"dx": dx, "key": key, "region": region}
    if page_url:
        job["pageUrl"] = page_url
    if user_agent:
        job["userAgent"] = user_agent
    if math_random is not None:
        job["mathRandom"] = math_random
    jf = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8")
    json.dump(job, jf)
    jf.close()
    argv = [node, os.path.join(here, "sentinel_dx.js"), "--job", jf.name]
    r = subprocess.run(argv, capture_output=True, text=True, encoding="utf-8",
                       timeout=120, cwd=here)
    try:
        os.unlink(jf.name)
    except OSError:
        pass
    t = (r.stdout or "").strip()
    if not t or len(t) < 200:
        err = t
        try:
            import base64 as _b
            err = _b.b64decode(t + "==").decode("utf-8", "replace")
        except Exception:
            pass
        raise RuntimeError(f"generate_t 失败: {err[:200]} | stderr: {(r.stderr or '')[:200]}")
    return t


def forge_t(collected: dict, key: str) -> str:
    """t 字段生成公式（03-md 三级装载实锤，dx-prog-1031-real/-inner/-inner2 三级验证）：
    t = b64( XOR( JSON.stringify(采集对象), String(K) ) )
    - 采集对象：键为浮点槽名；值含 Math.random、字体度量（b64(字符串)）、
      clientBootstrap（cfConnectingIp/cfIpCity/userRegion/cfIpLat/Lon）、
      navigator vendor/platform/deviceMemory/maxTouchPoints、screen/history/location、
      sdk.js flow 正则提取、localStorage("e27d00349246f6ca") 状态
    - K：L3 槽 16.31 的值（每挑战会话唯一；1031 实测一例 "20.47"）
    - 校准基准：analysis/protocol/t-collected-object-0-email_otp_validate.json（真实 t 反解）"""
    import base64
    raw = json.dumps(collected, separators=(",", ":"), ensure_ascii=False)
    xored = "".join(chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(raw))
    return base64.b64encode(xored.encode("latin1")).decode()


def build_sentinel_business_headers(ch: SentinelChallenge, p: str, t: str, so: str, flow: str) -> dict:
    """业务头构造（实测结构，10146/10807 验证）：
    openai-sentinel-token={p,t,c:token,id,flow}；openai-sentinel-so-token={so,c:token,id,flow}"""
    did = ""  # state.oai_did 注入
    return {
        "openai-sentinel-token": json.dumps({"p": p, "t": t, "c": ch.token, "id": did, "flow": flow}),
        "openai-sentinel-so-token": json.dumps({"so": so, "c": ch.token, "id": did, "flow": flow}),
    }


def build_extra_data_header(conversation_id: str, last_message_id: str,
                            sequence_number: int, signals: str) -> str:
    """openai-sentinel-extra-data 头（runtime-analysis.md §6 实证，源码 R() 提交路径）：
    base64url({v:1, conversation_id, last_message_id, sequence_number, signals})
    挂载位置：finalize / conversation 系请求；缓存 16 条 / 540s TTL（与 sentinel token 同窗）。"""
    import base64
    payload = {"v": 1, "conversation_id": conversation_id, "last_message_id": last_message_id,
               "sequence_number": sequence_number, "signals": signals}
    raw = json.dumps(payload, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def build_ping_request(requirements: dict, ping_path: str, *, proof_token: str = "",
                       turnstile_token: str = "", so_token: str = "",
                       conversation_id: str = "", last_message_id: str = "",
                       sequence_number: int = 0, ping_source: str = "conversation_heartbeat") -> dict:
    """sentinel ping POST（04-so-token.md R() 实证——新链路端点 requirements.pingPath）：
    credentials same-origin + keepalive；四 sentinel 头 + extra-data。
    signals 结构逐字段实测：so/turnstile/proof/prepare/chat_requirements 五个 *_present 位。"""
    signals = {
        "ping_source": ping_source,
        "so_token_present": "1" if so_token else "0",
        "turnstile_token_present": "1" if turnstile_token else "0",
        "proof_token_present": "1" if proof_token else "0",
        "prepare_token_present": "1" if requirements.get("prepare_token") else "0",
        "chat_requirements_token_present": "1" if requirements.get("token") else "0",
    }
    headers = {"Accept": "application/json"}
    if requirements.get("prepare_token"):
        headers["openai-sentinel-chat-requirements-prepare-token"] = requirements["prepare_token"]
    if requirements.get("token"):
        headers["openai-sentinel-chat-requirements-token"] = requirements["token"]
    if so_token:
        headers["openai-sentinel-so-token"] = so_token
    if proof_token:
        headers["openai-sentinel-proof-token"] = proof_token
    if turnstile_token:
        headers["openai-sentinel-turnstile-token"] = turnstile_token
    headers["openai-sentinel-extra-data"] = build_extra_data_header(
        conversation_id, last_message_id, sequence_number, signals)
    return {"url": ping_path, "headers": headers, "keepalive": True}


def heartbeat_interval_schedule(first_ms: int = 2000, cap_ms: int = 120_000, window_ms: int = 600_000):
    """心跳节奏（04-so-token.md K()/J() 实证）：2000ms 起、每次翻倍、上限 120s、总窗 600s 后清理。"""
    t, iv = 0, first_ms
    while t < window_ms and iv <= cap_ms:
        yield iv
        t += iv
        iv = min(iv * 2, cap_ms)
