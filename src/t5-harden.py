# T5 账号硬化纯协议：登录 → 密码设置 → TOTP MFA（1035/1036 抓包逆向）
# 用法: python t5-harden.py <email> <otp_hook> <region> <sid>
# 链路（无密码已存在账号 = 1036 validate#1 路径）:
#   login(NextAuth→authorize→sentinel→send-otp→hook→validate)
#   → continue_url=/reset-password/new-password → sentinel(password_reset) → password/add
#   → callback → session → GET /api/auth/session → Bearer accessToken
#   → mfa/enroll(totp) → 本地 TOTP 算码 → activate_enrollment → factor_decision
#   → CSV(含 password/totp_secret 新列) + tokens/<email>.json 双落档
import sys, os, json, time, re, pathlib, random, csv as _csv, hmac, hashlib, base64 as _b64, struct

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from build.live_engine import LiveEngine, proxy_url, navigation_headers, fetch_headers
from build.params.known import (pkce_verifier, pkce_challenge_s256, new_oauth_state,
                                new_logging_id, new_oai_did, build_sentinel_headers,
                                sentinel_error_fallback)
from build.params.env25 import fake_config25, region_config, REGION_PRESETS
from build.sentinel import requirements_token, solve_proofofwork, generate_t, generate_so
from types import SimpleNamespace
import uuid as _uuid

_args = sys.argv[1:]
EMAIL = _args[0]
OTP_HOOK = _args[1]
REGION = _args[2] if len(_args) > 2 else "JP"
SID = _args[3] if len(_args) > 3 else ("H" + "".join(random.choices("abcdefghjkmnpqrstuvwxyz23456789", k=9)))
_GATEWAY = os.environ.get("PROXY_HOST_SG", "<PROXY_HOST_SG>") if REGION in ("JP", "ID", "SG") else os.environ.get("PROXY_HOST_US", "<PROXY_HOST_US>")
PROXY = proxy_url(REGION, SID, host_tpl=_GATEWAY)
# [实验] 走窗口同款出口：T5_PROXY_FULL=http://user:pass@host:port
if os.environ.get("T5_PROXY_FULL"):
    PROXY = os.environ["T5_PROXY_FULL"]
    print(f"[实验] PROXY 覆盖为窗口同款: {PROXY.split('@')[-1]} sid={'-'.join(PROXY.split('sid-')[-1].split('-')[:1])}")
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36"
BASE = {
    "User-Agent": UA,
    "sec-ch-ua": '"Not;A=Brand";v="8", "Chromium";v="150", "Google Chrome";v="150"',
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": '"Windows"',
    "accept-language": "en-US,en;q=0.9",
}
# 账号密码（生成即存档）
PW_CHARS = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789!@#$%"
NEW_PASSWORD = "".join(random.choices(PW_CHARS, k=16))
# 既有账号的旧密码（改密用）——环境变量传入或已知值
OLD_PASSWORD = os.environ.get("T5_OLD_PASSWORD", "")
# 已存 TOTP secret（本号此前 MFA 激活 → 登录遇 mfa-challenge 需要它）
SAVED_TOTP = ""
CSV_PATH = pathlib.Path(__file__).with_name("registered-accounts.csv")
TRANSCRIPT = []
def log(*a):
    s = " ".join(str(x) for x in a)
    print(s, flush=True)
    TRANSCRIPT.append(s)

try:
    _tp = pathlib.Path(__file__).with_name("tokens") / f"{EMAIL.replace('@', '_at_')}.json"
    if _tp.exists():
        SAVED_TOTP = json.load(open(_tp, encoding="utf8")).get("totp_secret") or ""
except Exception:
    pass
if SAVED_TOTP:
    log(f"[MFA] 本号已有 TOTP secret（登录将遇 mfa-challenge）")

def datadog_ids():
    return str(random.getrandbits(63)), str(random.getrandbits(63))

def auth_api_base():
    return dict(BASE, **{
        "Referer": "https://auth.openai.com/",
        "x-access-flow-invocation-id": str(_uuid.uuid4()),
        "x-openai-document-navigation-id": NAVIGATION_ID,
    })

def add_datadog(h):
    trace_id, parent_id = datadog_ids()
    h.update({"x-datadog-trace-id": trace_id, "x-datadog-parent-id": parent_id,
              "x-datadog-origin": "rum", "x-datadog-sampling-priority": "1",
              "accept": "application/json"})
    return h

def hook_code():
    from curl_cffi import requests as cr
    from datetime import datetime
    try:
        r = cr.get(OTP_HOOK, verify=False, timeout=15)
        txt = r.text.strip()
        ts = None
        m = re.search(r"\b(\d{6})\b", txt)
        return (m.group(1) if m else None), ts
    except Exception:
        return None, None

def fetch_otp(max_wait_s=420):
    t0 = time.monotonic()
    pre_code, _ = hook_code()
    last = ""
    while time.monotonic() - t0 < max_wait_s:
        code, _ = hook_code()
        if code and code != pre_code:
            return code, "value_change"
        time.sleep(6)
    return None, last

def totp_now(secret_b32, period=30, digits=6):
    key = _b64.b32decode(secret_b32 + "=" * ((-len(secret_b32)) % 8))
    counter = int(time.time() // period)
    h = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    o = h[-1] & 0x0F
    code = (struct.unpack(">I", h[o:o+4])[0] & 0x7FFFFFFF) % (10 ** digits)
    return f"{code:0{digits}d}"

eng = LiveEngine(proxy=PROXY)
oai_did = new_oai_did()
logging_id = new_logging_id()
NAVIGATION_ID = str(_uuid.uuid4())
# ===== 设备级 cookie 引导（真窗实拍值）：档案积累的设备身份，认证页据此下发 usc/checksum 富化流 =====
# （__oailb/_dd_s/CF 系 IP 会话绑定不注入；这四件为长寿命设备级）
eng.jar._d[("openai.com", "oaicom-stable-id")] = ("104a03d3-b3c4-4590-9d89-cc262870bea0", "")
eng.jar._d[("openai.com", "__obi")] = ("ONjRTfkSVOpKX8rZE51jBQ", "")
eng.jar._d[("auth.openai.com", "rg_context")] = ("prim", "")
eng.jar._d[("auth.openai.com", "iss_context")] = ("default", "")
# ===== [实验] CF/LB 传输层注入（同出口 IP 前提下测 reauth 门）：T5_CF_INJECT=1 开 =====
if os.environ.get("T5_CF_INJECT") == "1":
    CF5 = {
        "_cfuvid": "yfKp09352h4zCIem_JzcpRGjHewjJTgiuKmyqRQ2gt4-1794969555.5068016-1.0.1.1-4caY6mWUDylQtTFY2EyGkf.g.8I.Ux81Oyxah1XhwFo",
        "__cflb": "0H28w2ZepuU3KZxNdeDWvQP2T9ciBUNBQaAgqVABx27",
        "cf_clearance": ("Cn87QSxOlCX5cZ3DL1CdcYZM0jucqvfMP7afzfiS0VGTLQYIjXo3oouchw5O9TAAdviOJT0dmH61IwsMsORSS_VLzZlLd1g1ZN8"
                         "-PTCoJMViG5v3Y4N1EEw8lmGKp33WpGSBvKFMHhCtXoxGnEQd-CUFSmkoxtRrQwfjL8l7zxxP3JEFO58EbzuyeOyTB47eDVLk1wJBl5pnjyskg5ON0pgCFcN5XFn2fpn5yXllIDMXXFkMQoo4wz3rjV1Hff4Mcxe-T0u3dtN_gIR1ge88CWHEkygSQpJxwBZ0flzaj8SeTmsQTtWRMMk"),
        "__cf_bm": "YXXKAr_fSIDCcxkzVkOBlFOJy.kJwshRl6t_lch5KfY-1794969450.2754173-1.0.1.1-ISjDOM3djYuJoJukqbaQUsXB34QFMh0NUWNlGR.H_SCv_lfB.GSviujyUA90.L53myGFvsSKxo7EEtiskEkgP0KPMFpFqDcjFFrlp5.SMU4jchvTttSLbVA20Q.3cnua",
        "__oailb": ("eyJhbGciOiJFUzI1NiIsImtpZCI6Im9haWxiLXYxIiwidHlwIjoiSldUIn0.eyJob3N0IjoiYXV0aGFwaS1sb2dpbi1wcm92aWRlci5nYXRld2F5LnVuaWZpZWQtMTYuYXBpLm9wZW5haS5jb20iLCJpc3MiOiJlZGdlLWdhdGV3YXkiLCJhdWQiOlsiYXV0aC5vcGVuYWkuY29tIl0sImV4cCI6MTc5NDk3NDExMywiaWF0IjoxNzk0OTY4NDEzfQ"
                     ".tqv0b3keEkC4LAZ0fL-Oh6z_2jsUPXMozAZkS36NKOw4oYiXwYy08202ZFSFXIL52cKvp8W-RQGfa1t1CZmE0A"),
    }
    for _nm, _vl in CF5.items():
        eng.jar._d[("auth.openai.com", _nm)] = (_vl, "")
    log("[实验] CF/LB 传输层五件已注入（auth.openai.com）")
st = SimpleNamespace(oai_did=oai_did, auth_session_logging_id=logging_id,
                     login_hint=EMAIL, oauth_state=new_oauth_state(),
                     code_challenge=pkce_challenge_s256(pkce_verifier()))
cfg = fake_config25(user_agent=UA, language="en-US", languages="en-US,en")
SENTINEL_FRAME_REFERER = "https://auth.openai.com/"

# 出口探测
EXIT_IP = ""
try:
    EXIT_IP = eng.get("https://api.ip.sb/ip").body.decode("utf8", "replace").strip()
    log(f"[PROBE] exit-ip={EXIT_IP} region={REGION} sid={SID}")
except Exception as e:
    log(f"[PROBE] 探测失败: {str(e)[:80]}")

def sentinel_round(flow):
    p = requirements_token(region_config(REGION, user_agent=UA))
    h = dict(BASE, **{
        "Content-Type": "text/plain;charset=UTF-8",
        "Referer": SENTINEL_FRAME_REFERER,
        "oai-language": REGION_PRESETS[REGION]["language"], "oai-device-id": oai_did,
    })
    r = eng.post("https://sentinel.openai.com/backend-api/sentinel/req",
                 json={"p": p, "id": oai_did, "flow": flow}, headers=h)
    obj = json.loads(r.body.decode("utf-8", "replace"))
    log(f"  [sentinel/{flow}] status={r.status} token_len={len(obj.get('token',''))} "
        f"dxLen={len((obj.get('turnstile') or {}).get('dx') or '')}")
    if r.status != 200:
        return None
    pw = obj.get("proofofwork") or {}
    proof = solve_proofofwork(str(pw.get("seed")), str(pw.get("difficulty")), list(cfg)) if pw.get("required") else ""
    ts = obj.get("turnstile") or {}
    t = generate_t(ts["dx"], p, region=REGION, user_agent=UA) if ts.get("required") and ts.get("dx") else ""
    so_obj = obj.get("so") or {}
    scen = "history-form" if flow in ("oauth_create_account", "password_reset") else "history-otp"
    so = generate_so(so_obj["collector_dx"], so_obj["snapshot_dx"], p, events=scen) if so_obj.get("required") else ""
    return {"c": obj["token"], "proof": proof, "t": t, "so": so, "p": p, "raw": obj}

def biz_headers(flow_name):
    mat = sentinel_round(flow_name)
    if not mat:
        return None, None
    hdrs = build_sentinel_headers(st, flow_name, challenge=mat["c"],
                                  dx=(mat["raw"].get("turnstile") or {}).get("dx", ""),
                                  key=mat["p"], proof_token=mat["proof"], so_token=mat["so"])
    h = add_datadog(auth_api_base())
    h["openai-sentinel-token"] = hdrs["openai-sentinel-token"]
    h["Content-Type"] = "application/json"
    if "openai-sentinel-so-token" in hdrs:
        h["openai-sentinel-so-token"] = hdrs["openai-sentinel-so-token"]
    return h, mat

REAUTH_PAGE_NAV = ""


def biz_headers2(flow_name, state_obj):
    """reauth 会话版：用 reauth authorize 的 state/challenge 造 sentinel 头（返回 (h, mat)）
    页面语义：reauth 落页 = 新 document → 后续 API 用页面级 nav-id（REAUTH_PAGE_NAV）"""
    mat = sentinel_round(flow_name)
    if not mat:
        return None, None
    hdrs = build_sentinel_headers(state_obj, flow_name, challenge=mat["c"],
                                  dx=(mat["raw"].get("turnstile") or {}).get("dx", ""),
                                  key=mat["p"], proof_token=mat["proof"], so_token=mat["so"])
    h = add_datadog(dict(BASE, **{
        "Referer": "https://auth.openai.com/",
        "x-access-flow-invocation-id": str(_uuid.uuid4()),
        "x-openai-document-navigation-id": REAUTH_PAGE_NAV or NAVIGATION_ID,
    }))
    h["openai-sentinel-token"] = hdrs["openai-sentinel-token"]
    h["Content-Type"] = "application/json"
    if "openai-sentinel-so-token" in hdrs:
        h["openai-sentinel-so-token"] = hdrs["openai-sentinel-so-token"]
    return h, mat

# ============ T5.0 NextAuth 正门（登录） ============
NEXTAUTH_LOGGING_ID = str(_uuid.uuid4())
h_csrf = dict(BASE, **fetch_headers(for_url="https://chatgpt.com/api/auth/csrf",
                                    init_url="https://chatgpt.com/", origin="https://chatgpt.com",
                                    referer="https://chatgpt.com/"))
r_csrf = eng.get("https://chatgpt.com/api/auth/csrf", headers=h_csrf)
csrf_token = json.loads(r_csrf.body.decode("utf-8", "replace")).get("csrfToken", "")
log(f"[T5.0] csrf: status={r_csrf.status} len={len(csrf_token)}")
if not csrf_token:
    log("[FATAL] csrf 未取得"); sys.exit(1)
signin_url = (f"https://chatgpt.com/api/auth/signin/openai?prompt=login"
              f"&auth_session_logging_id={NEXTAUTH_LOGGING_ID}&login_hint={EMAIL}")
h_signin = dict(BASE, **fetch_headers(for_url=signin_url, init_url="https://chatgpt.com/",
                                      origin="https://chatgpt.com", referer="https://chatgpt.com/",
                                      content_type="application/x-www-form-urlencoded",
                                      extra={"oai-language": REGION_PRESETS[REGION]["language"], "oai-device-id": oai_did}))
r_signin = eng.post(signin_url, data=f"callbackUrl=https%3A%2F%2Fchatgpt.com%2F&csrfToken={csrf_token}&json=true".encode(), headers=h_signin)
authorize_url = ""
try:
    authorize_url = json.loads(r_signin.body.decode("utf-8", "replace")).get("url", "")
except Exception:
    pass
if not authorize_url.startswith("http"):
    log("[FATAL] signin 未返回 authorize URL")
    sys.exit(1)
log(f"[T5.0] authorize_url: {authorize_url[:120]}")

# ============ T5.1 authorize ============
# 409/403 根因：authorize 走 curl_cffi 时 CF 403（指纹拦截）→ 会话废 → send-otp 409
# 成功轮次（barkers 等）恰好 CF 没拦（302 直过）→ 全链通
# 修复：登录 authorize 也走 Node 转发（JSD 解在前保证 cf_clearance + 同指纹）
h = dict(BASE, **navigation_headers(for_url=authorize_url, init_url="https://chatgpt.com/", referer="https://chatgpt.com/"))
try:
    from build.node_forwarder import NodeForwarder
    _fwd = NodeForwarder()
    # 引擎 cookie 同步
    for (tl, n), (v, _rw) in eng.jar._d.items():
        if "openai.com" in tl or "chatgpt.com" in tl:
            _fwd.p.stdin.write(json.dumps({"id": 910000 + len(v), "_setjar": True, "name": n, "value": v}) + "\n")
    _fwd.p.stdin.flush()
    time.sleep(0.3)
    _r1 = _fwd.request(authorize_url, headers=h)
    # 回收 Node jar → 引擎
    for _nm, _vl in (_r1.get("jar") or {}).items():
        eng.jar._d[("auth.openai.com", _nm)] = (_vl, "")
    class _R: pass
    r1 = _R()
    r1.status = _r1.get("status")
    r1.headers = _r1.get("headers") or {}
    r1.body = (_r1.get("body") or "").encode()
    log(f"[T5.1] authorize(Node): status={r1.status}")
    # follow 链也走 Node
    url_now = str(r1.headers.get("location") or "")
    for _ in range(4):
        if not url_now.startswith("http"):
            break
        _rf = _fwd.request(url_now, headers=dict(BASE, Referer="https://chatgpt.com/"))
        for _nm, _vl in (_rf.get("jar") or {}).items():
            eng.jar._d[("auth.openai.com", _nm)] = (_vl, "")
        nxt = str((_rf.get("headers") or {}).get("location") or "")
        if _rf.get("status") in (200, 403, 404) or not nxt:
            break
        url_now = nxt
    _fwd.close()
except Exception as _fe:
    log(f"[T5.1] Node 转发异常({str(_fe)[:70]}) → 引擎直发兜底")
    r1 = eng.get(authorize_url, headers=h)
    url_now = str(r1.headers.get("location") or "")
    for _ in range(4):
        if not url_now.startswith("http"):
            break
        r = eng.get(url_now, headers=dict(BASE, **navigation_headers(for_url=url_now, init_url="https://chatgpt.com/", referer="https://chatgpt.com/")))
        nxt = str(r.headers.get("location") or "")
        if r.status in (200, 403, 404) or not nxt:
            break
        url_now = nxt
    log(f"[T5.1] authorize: status={r1.status}")

# ============ T5.2 sentinel(authorize_continue) + send-otp ============
eng.human_pause()
h3, mat = biz_headers("authorize_continue")
if not h3:
    log("[FATAL] sentinel authorize_continue 失败"); sys.exit(1)
r3 = eng.post("https://auth.openai.com/api/accounts/passwordless/send-otp", json={}, headers=h3)
log(f"[T5.2] send-otp: status={r3.status}")
if r3.status != 200:
    log("[FATAL] send-otp 失败"); sys.exit(1)
SEND_TS = time.time()

# ============ T5.3 OTP 收码 ============
code, raw = fetch_otp()
log(f"[T5.3] OTP: {code}")
if not code:
    log("[FATAL] OTP 未收到"); sys.exit(1)

# ============ T5.4 validate（分流 continue_url） ============
eng.human_pause()
h4, mat = biz_headers("email_otp_validate")
if not h4:
    log("[FATAL] sentinel email_otp_validate 失败"); sys.exit(1)
r4 = eng.post("https://auth.openai.com/api/accounts/email-otp/validate", json={"code": code}, headers=h4)
t4 = r4.body.decode("utf-8", "replace")
obj4 = {}
try:
    obj4 = json.loads(t4)
except Exception:
    pass
cu4 = obj4.get("continue_url") or ""
log(f"[T5.4] validate: status={r4.status} continue_url={cu4[:80]}")
if r4.status != 200:
    log("[FATAL] validate 未通过"); sys.exit(1)

def try_reauth_password():
    """reauth 门 → 按落页分流 → password/add（1036：reauth 距登录 ~26s，会话亲和传播窗口）"""
    global PASSWORD_DONE, SEND_TS
    log("[T5.5w] 等待 25s（1036 实测 reauth 距登录 26s — 会话亲和传播）")
    time.sleep(25)
    # ============ T5.5 reauth 门：settings/security 的加密码入口 ============
    # 1035 实锤：signin(reauth=password&max_age=0&post_login_add_password=true)
    # → authorize(max_age=0) → 无 MFA 账号直接落 reset-password 页
    # ===== JSD 求解前置：CF 挑战 → cf_clearance 写回 jar（纯协议破解成果）=====
    try:
        from build.cf_jsd_solver import solve_jsd
        _ck = solve_jsd(eng, timeout_s=10)
        log(f"[T5.5j] JSD 解: {json.dumps({k: v[:20] + '…' for k, v in _ck.items()}, ensure_ascii=False)}")
        for _nm, _vl in _ck.items():
            if _nm.startswith("_"):
                continue
            eng.jar._d[("auth.openai.com", _nm)] = (_vl, "")
            eng.jar._d[("openai.com", _nm)] = (_vl, "")
    except Exception as _e:
        log(f"[T5.5j] JSD 解异常: {str(_e)[:100]}")
    # ===== settings 上下文先行（真窗实拍：reauth signin 前必访 settings/security + 整批 API 读）=====
    # 假说验证：reauth 会话要求客户端先建立 settings 上下文（eligibility/mfa_info/biometric-factors 批）
    eng.human_pause()
    _at = ""
    try:
        r_sess = eng.get("https://chatgpt.com/api/auth/session",
                         headers=dict(BASE, **fetch_headers(for_url="https://chatgpt.com/api/auth/session",
                                                            init_url="https://chatgpt.com/", origin="https://chatgpt.com",
                                                            referer="https://chatgpt.com/")))
        _at = json.loads(r_sess.body.decode("utf-8", "replace")).get("accessToken") or ""
        log(f"[T5.5s] 会话预探: accessToken={'✓' + str(len(_at)) if _at else '✗'}")
    except Exception:
        pass
    r_st = eng.get("https://chatgpt.com/settings/security",
                   headers=dict(BASE, **navigation_headers(for_url="https://chatgpt.com/settings/security",
                                                            init_url="https://chatgpt.com/", referer="https://chatgpt.com/")))
    log(f"[T5.5s] settings/security 页: status={r_st.status}")
    # Bearer 批（真窗 1036 序列逐项还原）
    if _at:
        sbh = dict(BASE, **{"Authorization": f"Bearer {_at}", "Accept": "application/json",
                            "Referer": "https://chatgpt.com/", "OAI-Language": "en-US",
                            "OAI-Device-Id": oai_did, "oai-did": oai_did})
        for ep in ("backend-api/accounts/check/v4-2023-04-27", "backend-api/settings/user",
                   "backend-api/accounts/security_settings/info", "backend-api/accounts/add_password/eligibility",
                   "backend-api/accounts/change_password/eligibility", "backend-api/accounts/mfa_info",
                   "backend-api/accounts/sessions", "backend-api/accounts/user_events?limit=20",
                   "backend-api/accounts/cyber_verification/status", "backend-api/accounts/security/recommendations",
                   "api/identity/service/biometric-factors", "backend-api/celsius/ws/user", "backend-api/me",
                   "backend-api/amphora/notifications?limit=20", "backend-api/accounts/optimized/check"):
            try:
                rr = eng.get("https://chatgpt.com/" + ep, headers=dict(sbh))
                log(f"  [settings批] {ep.split('/')[-1][:34]:36s} {rr.status}")
            except Exception as _e:
                log(f"  [settings批] {ep.split('/')[-1][:34]:36s} EXC {str(_e)[:40]}")
            eng.human_pause()
    eng.human_pause()
    h_csrf2 = dict(BASE, **fetch_headers(for_url="https://chatgpt.com/api/auth/csrf",
                                         init_url="https://chatgpt.com/", origin="https://chatgpt.com",
                                         referer="https://chatgpt.com/"))
    r_csrf2 = eng.get("https://chatgpt.com/api/auth/csrf", headers=h_csrf2)
    csrf2 = json.loads(r_csrf2.body.decode("utf-8", "replace")).get("csrfToken", "")
    signin2 = ("https://chatgpt.com/api/auth/signin/openai?prompt=login&screen_hint=login_or_signup"
               "&reauth=password&max_age=0&login_hint=" + EMAIL.replace("@", "%40")
               + "&post_login_add_password=true")
    h_s2 = dict(BASE, **fetch_headers(for_url=signin2, init_url="https://chatgpt.com/",
                                       origin="https://chatgpt.com", referer="https://chatgpt.com/",
                                       content_type="application/x-www-form-urlencoded"))
    r_s2 = eng.post(signin2, data=f"csrfToken={csrf2}&callbackUrl=https%3A%2F%2Fchatgpt.com%2Fsettings%2Fsecurity&json=true".encode(), headers=h_s2)
    s2txt = r_s2.body.decode("utf-8", "replace")
    log(f"[T5.5] reauth signin: status={r_s2.status} body={s2txt[:220]}")
    auth2 = ""
    try:
        auth2 = json.loads(s2txt).get("url", "")
    except Exception:
        pass
    if auth2.startswith("http"):
        # reauth = 全新 authorize：新 state/code_challenge → 新 st2（sentinel 头材料）
        from urllib.parse import urlparse as _up, parse_qs as _pq
        q2 = _pq(_up(auth2).query)
        st2 = SimpleNamespace(oai_did=oai_did, auth_session_logging_id=str(_uuid.uuid4()),
                              login_hint=EMAIL, oauth_state=q2.get("state", [""])[0],
                              code_challenge=q2.get("code_challenge", [""])[0])
        log(f"[T5.5] reauth state: len={len(st2.oauth_state)} challenge={st2.code_challenge[:20]}…")
        h5n = dict(BASE, **navigation_headers(for_url=auth2, init_url="https://chatgpt.com/", referer="https://chatgpt.com/"))
        try:
            _pre = {n: v[:24] for (tl, n), (v, _rw) in eng.jar._d.items() if "openai.com" in tl and n.startswith("auth-")}
            log(f"[T5.5]   reauth前 auth域会话cookie: {_pre}")
        except Exception:
            pass
        # === Node 转发层：reauth authorize 走 Node fetch（同指纹——CF clearance 绑定验证）===
        try:
            from build.node_forwarder import NodeForwarder
            _fwd = NodeForwarder()
            # 先把引擎的 cookie 同步到 Node jar
            for (tl, n), (v, _rw) in eng.jar._d.items():
                if "openai.com" in tl:
                    _fwd.p.stdin.write(json.dumps({"id": 900000 + len(_fwd.jar), "_setjar": True, "name": n, "value": v}) + "\n")
            _fwd.p.stdin.flush()
            time.sleep(0.3)
            r5n = _fwd.request(auth2, headers=h5n)
            loc5n = str((r5n.get("headers") or {}).get("location") or "")
            sc5n = []
            log(f"[T5.5] reauth authorize(Node): status={r5n.get('status')} loc={loc5n[:100]}")
            # 收 Node jar 回引擎
            for _nm, _vl in (r5n.get("jar") or {}).items():
                eng.jar._d[("auth.openai.com", _nm)] = (_vl, "")
            _fwd.close()
        except Exception as _fe:
            log(f"[T5.5] Node 转发异常({str(_fe)[:60]}) → 引擎直发兜底")
            r5n = eng.get(auth2, headers=h5n)
            loc5n = str(r5n.headers.get("location") or "")
            sc5n = [v for k, v in r5n.headers.items() if k.lower() == "set-cookie"]
            log(f"[T5.5] reauth authorize: status={r5n.status} loc={loc5n[:100]}")
            log(f"[T5.5]   set-cookies: {[c.split('=')[0] for c in sc5n][:6]}")
        # auth.openai.com cookie 诊断（409 排查：会话载体）
        try:
            _ck = [f"{n}({len(v)}={v[:20]}…)" for (tl, n), (v, _rw) in eng.jar._d.items() if "openai.com" in tl and n.startswith(("auth-", "oai-"))]
            log(f"[T5.5]   auth域 cookies: {_ck[:14]}")
        except Exception:
            pass
        # 会话 JWT 载荷解码（invalid_state 取证）
        try:
            import base64 as _b64
            _jwt = next(v for (tl, n), (v, _rw) in eng.jar._d.items() if n == "auth-session-minimized")
            _pl = _jwt.split(".")[1]
            _pl += "=" * (-len(_pl) % 4)
            _dec = _b64.urlsafe_b64decode(_pl).decode("utf-8", "replace")
            log(f"[T5.5]   会话JWT载荷: {_dec[:600]}")
        except Exception as _e:
            log(f"[T5.5]   会话JWT解码失败: {_e}")
        url5 = loc5n
        landed = ""
        for _ in range(5):
            if not url5.startswith("http"):
                break
            rr = eng.get(url5, headers=dict(BASE, **navigation_headers(for_url=url5, init_url="https://chatgpt.com/", referer="https://chatgpt.com/")))
            log(f"  [reauth-follow] {rr.status} {str(rr.url)[:90]}")
            if rr.status == 200:
                _body = rr.body.decode("utf-8", "replace")
                pathlib.Path(__file__).with_name("reauth-landing.html").write_text(_body, encoding="utf-8")
                m = re.search(r"__reactRouterContext\.streamEnvelopes?\s*=\s*(.{0,3000})", _body, re.S)
                _ctx = ""
                if m:
                    _ctx = m.group(1)
                else:
                    m2 = re.search(r'window\.__remixContext\s*=\s*(.{0,3000})', _body, re.S)
                    _ctx = m2.group(1) if m2 else _body[:1500]
                log(f"[T5.5]   落页HTML {len(_body)} 字符 → reauth-landing.html | ctx头: {_ctx[:400]}")
            landed = str(rr.url)
            nxt = str(rr.headers.get("location") or "")
            if rr.status in (200, 403, 404) or not nxt:
                break
            url5 = nxt
        # 落页 = 新 document → nav-id 由服务端在 loader 里签发（documentNavigationId），
        # 页面 JS 后续 API 全带它——引擎自编 uuid 不被会话认（invalid_state 嫌疑根因）
        global REAUTH_PAGE_NAV
        _body = _body if "_body" in dir() else (rr.body.decode("utf-8", "replace") if rr.status == 200 else "")
        if not _body and pathlib.Path(__file__).with_name("reauth-landing.html").exists():
            _body = pathlib.Path(__file__).with_name("reauth-landing.html").read_text(encoding="utf8", errors="replace")
        _mnav = re.search(r'"documentNavigationId":"([0-9a-f-]{36})', _body)
        if not _mnav:
            _mnav = re.search(r'documentNavigationId\\",\\"([0-9a-f-]{36})', _body)
        REAUTH_PAGE_NAV = _mnav.group(1) if _mnav else str(_uuid.uuid4())
        log(f"[T5.5]   服务端 documentNavigationId: {REAUTH_PAGE_NAV[:18]}… (来源={'页面签发✓' if _mnav else '随机回退'})")
        # ===== reauth 重认证：无 MFA 账号直试 password/add（1035 实测 MFA 账号才需挑战；
        #      email-verification 落页但 reauth send-otp 409 会话已推进 → 直接按 st2 打密码步骤）=====
        # ===== reauth 重认证：按落页分流 =====
        # 1035 实测（有 MFA 号）：authorize → email-verification → send-otp(降级头) → validate
        #   → mfa-challenge → issue_challenge → mfa/verify → reset-password → password/add
        # 有 MFA 号的 reauth 可能直接落 mfa-challenge（MFA 即重认证）；无 MFA 号落 email-verification
        eng.human_pause()
        reauth_factor = ""
        if "mfa-challenge" in landed:
            # reauth 直接落 MFA 挑战 → issue_challenge + verify → 密码页
            reauth_factor = landed.split("?")[0].rstrip("/").split("/")[-1]
            log(f"[T5.5r] reauth 落 mfa-challenge: factor={reauth_factor}")
        elif "email-verification" in landed:
            # ===== 真窗实拍（run ed678b3a）：reauth 的邮件发送 = POST /api/accounts/email-otp/resend
            # 空 body、无 sentinel 头、纯会话 cookie。此前错打 passwordless/send-otp → 恒 409。=====
            eng.human_pause()
            h_rs = dict(BASE, **{
                "Referer": "https://auth.openai.com/",
                "Origin": "https://auth.openai.com",
                "Accept": "*/*",
                "Content-Type": "application/json",
                "x-access-flow-invocation-id": str(_uuid.uuid4()),
                "x-openai-document-navigation-id": REAUTH_PAGE_NAV or NAVIGATION_ID,
            })
            rso = eng.post("https://auth.openai.com/api/accounts/email-otp/resend", json={}, headers=h_rs)
            log(f"[T5.5b] reauth resend: status={rso.status} body={rso.body.decode('utf-8','replace')[:120]}")
            code2 = ""
            if rso.status in (200, 201, 202):
                SEND_TS = time.time()
                code2, _raw = fetch_otp()
                log(f"[T5.5c] reauth 新码: {code2}")
            if code2:
                h4b, _ = biz_headers2("email_otp_validate", st2)
                if h4b:
                    r4b = eng.post("https://auth.openai.com/api/accounts/email-otp/validate",
                                   json={"code": code2}, headers=h4b)
                    _t4b = r4b.body.decode("utf-8", "replace")
                    log(f"[T5.5d] reauth validate(新码): status={r4b.status} body={_t4b[:200]}")
                    cu4b = ""
                    try:
                        cu4b = json.loads(_t4b).get("continue_url", "")
                    except Exception:
                        pass
                    if "mfa-challenge" in cu4b:
                        reauth_factor = cu4b.split("?")[0].rstrip("/").split("/")[-1]
                        log(f"[T5.5r] reauth validate 落 mfa-challenge: factor={reauth_factor}")
                    elif "reset-password" in cu4b:
                        eng.get(cu4b, headers=dict(BASE, **navigation_headers(
                            for_url=cu4b, init_url="https://auth.openai.com/", referer="https://auth.openai.com/")))
                        # 无密码无 MFA 号：validate 直落密码页 → 立即 password/add
                        eng.human_pause()
                        h5d, _ = biz_headers2("password_reset", st2)
                        if h5d:
                            r5d = eng.post("https://auth.openai.com/api/accounts/password/add",
                                           json={"password": NEW_PASSWORD}, headers=h5d)
                            t5d = r5d.body.decode("utf-8", "replace")
                            obj5d = {}
                            try:
                                obj5d = json.loads(t5d)
                            except Exception:
                                obj5d = {}
                            log(f"[T5.5r] 直落密码页 add: status={r5d.status} head={t5d[:140]}")
                            if r5d.status == 200 and "code=" in (obj5d.get("continue_url") or ""):
                                PASSWORD_DONE = True
                                global PASSWORD_SET_DIRECT
                                eng.get(obj5d["continue_url"], headers=dict(BASE, **fetch_headers(
                                    for_url=obj5d["continue_url"], init_url="https://auth.openai.com/",
                                    referer="https://auth.openai.com/")))
                                log("[T5.5r] ✅ 纯协议加密码完成（直落路径）")
            else:
                log("[T5.5b] resend 未成 → 回退登录码直验")
                eng.human_pause()
                h4b, _ = biz_headers2("email_otp_validate", st2)
                if h4b:
                    r4b = eng.post("https://auth.openai.com/api/accounts/email-otp/validate",
                                   json={"code": code}, headers=h4b)
                    _t4b = r4b.body.decode("utf-8", "replace")
                    log(f"[T5.5d] reauth validate(登录码回退): status={r4b.status} body={_t4b[:200]}")
                    cu4b = ""
                    try:
                        cu4b = json.loads(_t4b).get("continue_url", "")
                    except Exception:
                        pass
                    if "mfa-challenge" in cu4b:
                        reauth_factor = cu4b.split("?")[0].rstrip("/").split("/")[-1]
                        log(f"[T5.5r] reauth validate 落 mfa-challenge: factor={reauth_factor}")
                    elif "reset-password" in cu4b:
                        eng.get(cu4b, headers=dict(BASE, **navigation_headers(
                            for_url=cu4b, init_url="https://auth.openai.com/", referer="https://auth.openai.com/")))
        if reauth_factor and SAVED_TOTP:
            # ===== MFA 重认证：issue_challenge（无 sentinel 头）+ mfa/verify [verify_mfa] =====
            h_ic = add_datadog(auth_api_base())
            h_ic["Content-Type"] = "application/json"
            r_ic = eng.post("https://auth.openai.com/api/accounts/mfa/issue_challenge",
                            json={"id": reauth_factor, "type": "totp", "force_fresh_challenge": False}, headers=h_ic)
            log(f"[T5.5r] issue_challenge: status={r_ic.status}")
            eng.human_pause()
            h_mv, _ = biz_headers2("verify_mfa", st2)
            if h_mv:
                tc2 = totp_now(SAVED_TOTP)
                log(f"[T5.5r] TOTP 算码: {tc2}")
                time.sleep(2)
                r_mv = eng.post("https://auth.openai.com/api/accounts/mfa/verify",
                                json={"id": reauth_factor, "type": "totp", "code": tc2}, headers=h_mv)
                t_mv = r_mv.body.decode("utf-8", "replace")
                cu_mv = ""
                try:
                    cu_mv = json.loads(t_mv).get("continue_url", "")
                except Exception:
                    pass
                log(f"[T5.5r] mfa/verify: status={r_mv.status} → {cu_mv[:80]}")
                if "reset-password" in cu_mv:
                    eng.get(cu_mv, headers=dict(BASE, **navigation_headers(
                        for_url=cu_mv, init_url="https://auth.openai.com/", referer="https://auth.openai.com/")))
                    # ===== 密码页落定 → password/add [sentinel password_reset, st2] =====
                    eng.human_pause()
                    h5, mat = biz_headers2("password_reset", st2)
                    if h5:
                        r5 = eng.post("https://auth.openai.com/api/accounts/password/add",
                                      json={"password": NEW_PASSWORD}, headers=h5)
                        t5 = r5.body.decode("utf-8", "replace")
                        obj5 = {}
                        try:
                            obj5 = json.loads(t5)
                        except Exception:
                            obj5 = {}
                        log(f"[T5.5r] password/add: status={r5.status} head={t5[:140]}")
                        # 已有密码（reauth 场景 400 already-have-password）→ 走 reset 改新密码
                        if r5.status == 400 and "already have a password" in t5:
                            log("[T5.5r] 已有密码 → 走 password/reset（带旧密码改新密）")
                            r5b = eng.post("https://auth.openai.com/api/accounts/password/reset",
                                           json={"current_password": OLD_PASSWORD, "password": NEW_PASSWORD}, headers=h5)
                            if r5b.status == 400:
                                # 试无旧密码形态
                                r5b = eng.post("https://auth.openai.com/api/accounts/password/reset",
                                               json={"password": NEW_PASSWORD}, headers=h5)
                            t5 = r5b.body.decode("utf-8", "replace")
                            try:
                                obj5 = json.loads(t5)
                            except Exception:
                                obj5 = {}
                            log(f"[T5.5r] password/reset: status={r5b.status} head={t5[:500]}")
                            r5 = r5b
                        try:
                            obj5 = json.loads(t5)
                        except Exception:
                            obj5 = {}
                        log(f"[T5.6] password/add: status={r5.status} head={t5[:110]}")
                        if r5.status == 200 and "code=" in (obj5.get("continue_url") or ""):
                            PASSWORD_DONE = True
                            r6b = eng.get(obj5["continue_url"], headers=dict(BASE, **fetch_headers(
                                for_url=obj5["continue_url"], init_url="https://auth.openai.com/", referer="https://auth.openai.com/")))
                            log(f"[T5.6b] callback: status={r6b.status}")
                            if r6b.status in (301, 302, 303):
                                nxt = str(r6b.headers.get("location") or "")
                                if nxt.startswith("http"):
                                    eng.get(nxt, headers=dict(BASE, Referer="https://chatgpt.com/"))
                        elif r5.status == 409:
                            log("[T5.6] 409 已有密码（改密走另一路径）")

PASSWORD_DONE = False
if "mfa-challenge" in cu4:
    # ============ TOTP 已激活账号：登录遇 MFA 挑战（1035 实测链） ============
    factor_id = cu4.split("?")[0].rstrip("/").split("/")[-1]
    log(f"[T5.4m] MFA 挑战: factor={factor_id}")
    if not SAVED_TOTP:
        log("[FATAL] 本号有 MFA 但 tokens/ 无 secret — 无法自动过挑战"); sys.exit(1)
    eng.human_pause()
    # issue_challenge：无 sentinel 头（1035 实测）
    h_ic = add_datadog(auth_api_base())
    h_ic["Content-Type"] = "application/json"
    r_ic = eng.post("https://auth.openai.com/api/accounts/mfa/issue_challenge",
                    json={"id": factor_id, "type": "totp", "force_fresh_challenge": False}, headers=h_ic)
    log(f"[T5.4m] issue_challenge: status={r_ic.status}")
    # verify：sentinel(verify_mfa) + 本地 TOTP 码
    eng.human_pause()
    h_mv, mat = biz_headers("verify_mfa")
    if not h_mv:
        log("[FATAL] sentinel verify_mfa 失败"); sys.exit(1)
    tc = totp_now(SAVED_TOTP)
    log(f"[T5.4m] TOTP 算码: {tc}")
    time.sleep(2)
    r_mv = eng.post("https://auth.openai.com/api/accounts/mfa/verify",
                    json={"id": factor_id, "type": "totp", "code": tc}, headers=h_mv)
    t_mv = r_mv.body.decode("utf-8", "replace")
    cu_mv = ""
    try:
        cu_mv = json.loads(t_mv).get("continue_url", "")
    except Exception:
        pass
    log(f"[T5.4m] mfa/verify: status={r_mv.status} → {cu_mv[:80]}")
    if "reset-password" in cu_mv:
        eng.get(cu_mv, headers=dict(BASE, **navigation_headers(
            for_url=cu_mv, init_url="https://auth.openai.com/", referer="https://auth.openai.com/")))
        eng.human_pause()
        h5, mat = biz_headers("password_reset")
        if h5:
            r5 = eng.post("https://auth.openai.com/api/accounts/password/add",
                          json={"password": NEW_PASSWORD}, headers=h5)
            t5 = r5.body.decode("utf-8", "replace")
            obj5 = {}
            try:
                obj5 = json.loads(t5)
            except Exception:
                obj5 = {}
            log(f"[T5.6] password/add: status={r5.status} head={t5[:110]}")
            if r5.status == 200 and "code=" in (obj5.get("continue_url") or ""):
                PASSWORD_DONE = True
                r6b = eng.get(obj5["continue_url"], headers=dict(BASE, **fetch_headers(
                    for_url=obj5["continue_url"], init_url="https://auth.openai.com/", referer="https://auth.openai.com/")))
                log(f"[T5.6b] callback: status={r6b.status}")
                if r6b.status in (301, 302, 303):
                    nxt = str(r6b.headers.get("location") or "")
                    if nxt.startswith("http"):
                        eng.get(nxt, headers=dict(BASE, Referer="https://chatgpt.com/"))
    elif "code=ac." in cu_mv or "callback" in cu_mv:
        log("[T5.4m] MFA 通过 → 直接 callback（登录完成，无密码页）")
        r6 = eng.get(cu_mv, headers=dict(BASE, **fetch_headers(
            for_url=cu_mv, init_url="https://auth.openai.com/", referer="https://auth.openai.com/")))
        if r6.status in (301, 302, 303):
            nxt = str(r6.headers.get("location") or "")
            if nxt.startswith("http"):
                eng.get(nxt, headers=dict(BASE, Referer="https://chatgpt.com/"))
    try_reauth_password()
elif "code=ac." in cu4 or "callback/openai" in cu4:
    # ============ 已存在账号：validate 直接签发 code → callback → 会话 ============
    log("[T5.4b] 已存在账号 — validate 直接签发 code，登录完成")
    r6 = eng.get(cu4, headers=dict(BASE, **fetch_headers(for_url=cu4, init_url="https://auth.openai.com/", referer="https://auth.openai.com/")))
    log(f"[T5.4c] callback: status={r6.status}")
    if r6.status in (301, 302, 303):
        nxt = str(r6.headers.get("location") or "")
        if nxt.startswith("http"):
            eng.get(nxt, headers=dict(BASE, Referer="https://chatgpt.com/"))
    try_reauth_password()
elif "reset-password/new-password" in cu4:
    # ============ 注册中会话：validate 落密码页（1036 全新号路径） ============
    eng.human_pause()
    h5, mat = biz_headers("password_reset")
    if not h5:
        log("[FATAL] sentinel password_reset 失败"); sys.exit(1)
    r5 = eng.post("https://auth.openai.com/api/accounts/password/add",
                  json={"password": NEW_PASSWORD}, headers=h5)
    t5 = r5.body.decode("utf-8", "replace")
    obj5 = {}
    try:
        obj5 = json.loads(t5)
    except Exception:
        pass
    log(f"[T5.5] password/add: status={r5.status} head={t5[:110]}")
    if r5.status == 200 and "code=" in (obj5.get("continue_url") or ""):
        PASSWORD_DONE = True
        r6 = eng.get(obj5["continue_url"], headers=dict(BASE, **fetch_headers(
            for_url=obj5["continue_url"], init_url="https://auth.openai.com/", referer="https://auth.openai.com/")))
        log(f"[T5.6] callback: status={r6.status}")
        if r6.status in (301, 302, 303):
            nxt = str(r6.headers.get("location") or "")
            if nxt.startswith("http"):
                eng.get(nxt, headers=dict(BASE, Referer="https://chatgpt.com/"))
else:
    log(f"[T5.5] continue_url 未知形态: {cu4[:80]}")

# ============ T5.7 会话 → Bearer accessToken ============
r8 = eng.get("https://chatgpt.com/api/auth/session",
             headers=dict(BASE, **fetch_headers(for_url="https://chatgpt.com/api/auth/session",
                                                init_url="https://chatgpt.com/", origin="https://chatgpt.com",
                                                referer="https://chatgpt.com/")))
t8 = r8.body.decode("utf-8", "replace")
ACCESS_TOKEN = ""
try:
    ACCESS_TOKEN = json.loads(t8).get("accessToken") or ""
except Exception:
    pass
log(f"[T5.7] session: status={r8.status} accessToken={'✓ ' + str(len(ACCESS_TOKEN)) + ' 字符' if ACCESS_TOKEN else '✗'}")
if not ACCESS_TOKEN:
    log("[FATAL] 无 accessToken — 后续 MFA 无法进行"); sys.exit(1)

# ============ T5.8 mfa/enroll(totp) → secret（mfa_info 守卫：已有 TOTP 则跳过） ============
bh = dict(BASE, **{"Authorization": f"Bearer {ACCESS_TOKEN}", "Content-Type": "application/json",
                   "Referer": "https://chatgpt.com/settings/security"})
r_mi = eng.get("https://chatgpt.com/backend-api/accounts/mfa_info",
               headers=dict(bh, **{"Content-Type": None} if False else {}))
mi = {}
try:
    mi = json.loads(r_mi.body.decode("utf-8", "replace"))
except Exception:
    pass
existing_totp = ((mi.get("factors") or {}).get("totp")) or []
TOTP_SECRET, TOTP_SESSION = "", ""
if existing_totp:
    log(f"[T5.8] mfa_info: TOTP 已激活（{len(existing_totp)} 因子）— 跳过 enroll")
    # 已激活：沿用 tokens 档案里的密钥记录（不再新造因子）
    TOTP_SECRET = SAVED_TOTP or ""
    TOTP_SESSION = ""
    ACT_OK = bool(TOTP_SECRET)
else:
    r9 = eng.post("https://chatgpt.com/backend-api/accounts/mfa/enroll",
                  json={"factor_type": "totp", "source": "settings"}, headers=bh)
    t9 = r9.body.decode("utf-8", "replace")
    obj9 = {}
    try:
        obj9 = json.loads(t9)
    except Exception:
        pass
    TOTP_SECRET = obj9.get("secret") or ""
    TOTP_SESSION = obj9.get("session_id") or ""
    log(f"[T5.8] mfa/enroll: status={r9.status} secret={'✓ ' + TOTP_SECRET if TOTP_SECRET else '✗'}")
    if not TOTP_SECRET:
        log("[FATAL] TOTP secret 未取得"); sys.exit(1)

    # ============ T5.9 本地 TOTP 算码 → activate ============
    tc = totp_now(TOTP_SECRET)
    log(f"[T5.9] TOTP 本地算码: {tc}")
    time.sleep(2)
    r10 = eng.post("https://chatgpt.com/backend-api/accounts/mfa/user/activate_enrollment",
                   json={"factor_type": "totp", "session_id": TOTP_SESSION, "code": tc, "source": "settings"}, headers=bh)
    t10 = r10.body.decode("utf-8", "replace")
    log(f"[T5.9] activate: status={r10.status} body={t10[:60]}")
    ACT_OK = '"success":true' in t10.replace(" ", "")

# ============ T5.10 factor_decision ============
r11 = eng.post("https://chatgpt.com/backend-api/accounts/mfa/factor_decision",
               json={"entrypoint": "post_totp"}, headers=bh)
log(f"[T5.10] factor_decision: status={r11.status}")

# ============ T5.11 team-1-month-free 促销资格检测（长链脚本第 3 步同款判定）============
TEAM_PROMO = ""
TEAM_PROMO_STATE = ""
try:
    h_cc = dict(BASE, Referer="https://chatgpt.com/", Accept="*/*")
    if ACCESS_TOKEN:
        h_cc["Authorization"] = "Bearer " + ACCESS_TOKEN
    r_cc = eng.get("https://chatgpt.com/backend-api/promo_campaign/check_coupon"
                   "?coupon=team-1-month-free&is_coupon_from_query_param=false", headers=h_cc)
    t_cc = r_cc.body.decode("utf-8", "replace")
    try:
        j_cc = json.loads(t_cc)
        TEAM_PROMO_STATE = j_cc.get("state", "?")
        rd = j_cc.get("redemption") or {}
        rd_str = (f" redeemed_at={rd.get('redeemed_at')}" if rd.get("redeemed_at") else "")
        log(f"[T5.11] team-1-month-free: state={TEAM_PROMO_STATE}{rd_str}")
    except Exception:
        log(f"[T5.11] team-1-month-free: 解析失败 body={t_cc[:120]}")
except Exception as e:
    log(f"[T5.11] team-1-month-free 检测异常: {str(e)[:80]}")

# ============ 落档：CSV 新列 + tokens json ============
st0 = st1 = ""
try:
    for (tail, name), (val, _raw) in eng.jar._d.items():
        if name.endswith("session-token.0"):
            st0 = val
        elif name.endswith("session-token.1"):
            st1 = val
except Exception:
    pass
STATUS = "harden-success" if (PASSWORD_DONE and ACT_OK) else ("mfa-success" if ACT_OK else "harden-failed")
# 档案完整性：password/add 未成功 → password 列留空（不得记入未生效的生成值）
REC_PASSWORD = NEW_PASSWORD if PASSWORD_DONE else ""
REC_TOTP = TOTP_SECRET if ACT_OK else ""
NOTES = (f"password={'✓已设置' if PASSWORD_DONE else '✗reauth-409未落'} totp={'✓' if ACT_OK else '✗'}"
         f" validate→{cu4.split('/')[-1][:28]}")
# ===== 账号表输出：accounts-clean.csv（一行一账号，按 email upsert 合并最新非空值）=====
# 格式规范：与 build/accounts-clean.csv 一致（用户指定的默认导出格式）
CLEAN_HDR = ["email", "region", "proxy_sid", "gateway", "status", "profile", "exit_ip",
             "password", "totp_secret", "session_token_0", "session_token_1", "access_token",
             "notes", "last_update", "alive", "team_promo"]
STATUS_RANK = {"failed": 0, "success": 1, "login-success": 2, "mfa-success": 3, "harden-success": 4, "harden-failed": 0}
CLEAN_PATH = CSV_PATH.with_name("accounts-clean.csv")
clean_rows = []
if CLEAN_PATH.exists():
    try:
        with open(CLEAN_PATH, encoding="utf-8-sig") as f:
            clean_rows = list(_csv.DictReader(f))
    except Exception:
        clean_rows = []
# 本轮结果行
this = {h: "" for h in CLEAN_HDR}
this.update({"email": EMAIL, "region": REGION, "proxy_sid": SID, "gateway": _GATEWAY,
             "status": STATUS, "exit_ip": EXIT_IP,
             "password": REC_PASSWORD, "totp_secret": REC_TOTP,
             "session_token_0": st0, "session_token_1": st1, "access_token": ACCESS_TOKEN,
             "notes": NOTES[:220], "last_update": time.strftime("%Y-%m-%d %H:%M:%S"),
             "alive": "YES" if ACT_OK else "", "team_promo": TEAM_PROMO_STATE})
# upsert：同 email 合并（时间递增 → 非空覆盖旧值；状态取最高）
merged = {}
for r in clean_rows:
    merged[r.get("email", "")] = r
m = merged.get(EMAIL, {h: "" for h in CLEAN_HDR})
for h in CLEAN_HDR:
    if this[h]:
        m[h] = this[h]
if STATUS_RANK.get(STATUS, -1) >= STATUS_RANK.get(m.get("status", ""), -1):
    m["status"] = STATUS
m["last_update"] = this["last_update"]
merged[EMAIL] = m
with open(CLEAN_PATH, "w", newline="", encoding="utf-8-sig") as f:
    w = _csv.DictWriter(f, fieldnames=CLEAN_HDR)
    w.writeheader()
    for e in merged:
        w.writerow({h: (merged[e].get(h) or "") for h in CLEAN_HDR})
log(f"[CSV] 账号表已更新 → accounts-clean.csv（{len(merged)} 账号，upsert: {EMAIL}）")
# 原流水日志（registered-accounts.csv）保留为调试痕迹，继续追加
LOG_HDR = ["timestamp", "email", "region", "proxy_sid", "gateway", "status", "profile", "exit_ip",
           "notes", "session_token_0", "session_token_1", "access_token", "password", "totp_secret"]
old_rows = []
if CSV_PATH.exists():
    try:
        old_rows = [r for r in _csv.reader(open(CSV_PATH, encoding="utf-8-sig"))][1:]
        old_rows = [r for r in old_rows if r and r[0] != LOG_HDR[0]]
    except Exception:
        old_rows = []
with open(CSV_PATH, "w", newline="", encoding="utf-8-sig") as f:
    w = _csv.writer(f)
    w.writerow(LOG_HDR)
    for r in old_rows:
        w.writerow(r + [""] * (len(LOG_HDR) - len(r)))
    w.writerow([time.strftime("%Y-%m-%d %H:%M:%S"), EMAIL, REGION, SID, _GATEWAY, STATUS,
                "", EXIT_IP, NOTES[:220], st0, st1, ACCESS_TOKEN, REC_PASSWORD, REC_TOTP])
tokdir = pathlib.Path(__file__).with_name("tokens")
tokdir.mkdir(exist_ok=True)
tf = tokdir / f"{EMAIL.replace('@', '_at_')}.json"
prev = {}
try:
    prev = json.load(open(tf, encoding="utf8"))
except Exception:
    pass
prev.update({"email": EMAIL, "region": REGION, "status": STATUS, "password": REC_PASSWORD,
             "totp_secret": REC_TOTP, "totp_session_id": TOTP_SESSION,
             "mfa_active": ACT_OK, "password_set": PASSWORD_DONE,
             "access_token": ACCESS_TOKEN, "session_token_0": st0, "session_token_1": st1,
             "team_promo": TEAM_PROMO_STATE,
             "hardened_at": time.strftime("%Y-%m-%d %H:%M:%S")})
tf.write_text(json.dumps(prev, ensure_ascii=False, indent=1), encoding="utf8")
log(f"[CSV] {STATUS} 已记录（password{'✓已设置' if PASSWORD_DONE else '✗未落(空列)'} + totp{'✓' if ACT_OK else '✗'}）")
log(f"[DONE] password={'✓' + REC_PASSWORD if PASSWORD_DONE else '✗reauth-409未设置'} | totp_secret={'✓' + REC_TOTP if REC_TOTP else '✗'} | team_promo={TEAM_PROMO_STATE or '?'}")
pathlib.Path(__file__).with_name("t5-transcript.txt").write_text("\n".join(TRANSCRIPT), encoding="utf8")
