# 纯协议注册链编排（骨架 v1）
# 链路顺序依据：analysis/window-1030/protocol-review.md 实测时序 + 四run抓包
# 待 A/B/C 分析产出后逐模块替换占位实现
from __future__ import annotations
import time, hashlib, base64, secrets
from dataclasses import dataclass, field
from .params.known import *
from .params.env25 import fake_config25, acquisition_names
from .sentinel import (SentinelChallenge, parse_sentinel_response, solve_proofofwork,
                       requirements_token, generate_t, build_sentinel_business_headers)
from .tls_engine import HttpEngine, HttpResponse


@dataclass
class SessionState:
    """会话状态容器：cookie、设备标识、认证会话、sentinel 材料"""
    cookies: dict = field(default_factory=dict)          # cookie_jar 接管
    oai_did: str = ""                                    # 设备ID（生成逻辑见 params/known.py）
    user_agent: str = ""                                 # 环境伪造（env25）用 UA
    language: str = "en-US"                              # 区域语言（JP/US=en-US, IN=hi-IN, ID=id-ID）
    languages: str = "en-US,en"
    auth_session_logging_id: str = ""
    login_hint: str = ""                                 # 邮箱
    oauth_state: str = ""
    code_challenge: str = ""
    code_verifier: str = ""
    sentinel_cache: dict = field(default_factory=dict)   # flow -> {token, expire_at}（9*60*1000ms 缓存）
    conduit_token: str = ""
    obi_token: str = ""
    access_token: str = ""


class RegistrationFlow:
    """注册链状态机，顺序与时序对齐实测抓包：

    1. GET  auth.openai.com/oauth/authorize          (302)
    2. POST sentinel.openai.com/backend-api/sentinel/req          flow=authorize_continue
    3. POST auth.openai.com/api/accounts/passwordless/send-otp    (200)
    4. GET  auth.openai.com/email-verification                    (页面)
    5. POST auth.openai.com/api/accounts/email-otp/validate       (200, body 仅 code)
    6. POST sentinel.openai.com/backend-api/sentinel/req          flow=email_otp_validate
    7. POST auth.openai.com/api/accounts/create_account           (200, body name+birthdate)
    8. POST sentinel.openai.com/backend-api/sentinel/req          flow=oauth_create_account
    9. GET  chatgpt.com/api/auth/callback/openai?code&scope&state (302)
    10. POST chatgpt.com/backend-api/sentinel/chat-requirements/prepare  (登录态, 607B body)
    11. POST chatgpt.com/backend-api/sentinel/chat-requirements/finalize (6.6-6.7KB body:
        {prepare_token, proofofwork, turnstile} — records 11360 JS 证据)
    12. POST chatgpt.com/backend-api/conversation/init            (Bearer, 172-206B)
    13. POST chatgpt.com/backend-api/bazaar/obi/sync-token        (50B body)
    14. POST bzr.openai.com/v1/obi/sync                           (1208B body, 204)
    """
    def __init__(self, engine: HttpEngine, state: SessionState):
        self.engine = engine
        self.state = state

    # ---- PKCE / state（确定性，本地可验证） ----
    def new_pkce(self):
        self.state.code_verifier = pkce_verifier()
        self.state.code_challenge = pkce_challenge_s256(self.state.code_verifier)

    # ---- 步骤1 ----
    def step1_authorize(self):
        q = build_authorize_query(self.state)
        return self.engine.get("https://auth.openai.com/oauth/authorize", params=q)

    # ---- 步骤2：sentinel 取挑战（流程名 authorize_continue）----
    # 请求体形状实测（1031）：{"p": requirements token gAAAAAC…, "id": oai-device-id, "flow"}
    # 响应含 {token(c), dx, …}；p/t/c/id/flow 组装进业务头（known.build_sentinel_headers）
    def step2_sentinel(self, flow: str):
        cfg = fake_config25(user_agent=self.state.user_agent, language=self.state.language,
                            languages=self.state.languages)
        body = build_sentinel_req_body(self.state, flow, cfg)
        return self.engine.post("https://sentinel.openai.com/backend-api/sentinel/req", json=body)

    # ---- 步骤3 ----
    def step3_send_otp(self):
        # 实测：send-otp 无 query 无 body；openai-sentinel-token 可为错误包装 {"e":"k9d4s6v3b2"}
        headers = build_sentinel_headers(self.state, flow="authorize_continue", error_fallback=True)
        return self.engine.post("https://auth.openai.com/api/accounts/passwordless/send-otp", headers=headers)

    # ---- 步骤5/7：validate / create_account（完整 sentinel 双头 {p,t,c,id,flow}）----
    def _complete_sentinel_headers(self, flow: str):
        """从 sentinel_cache 取 {challenge, dx, key, so} 并组装完整业务头。"""
        mat = self.state.sentinel_cache[flow]
        cfg = fake_config25(user_agent=self.state.user_agent, language=self.state.language,
                            languages=self.state.languages)
        proof = solve_proofofwork(mat["difficulty_seed"], mat["difficulty"], list(cfg))
        return build_sentinel_headers(self.state, flow, challenge=mat["challenge"], dx=mat["dx"],
                                      key=mat["key"], proof_token=proof, so_token=mat.get("so", ""))

    def step5_validate_otp(self, code: str):
        headers = self._complete_sentinel_headers("email_otp_validate")
        return self.engine.post("https://auth.openai.com/api/accounts/email-otp/validate",
                                json={"code": code}, headers=headers)

    # ---- 步骤7 ----
    def step7_create_account(self, name: str, birthdate: str):
        headers = self._complete_sentinel_headers("oauth_create_account")
        return self.engine.post("https://auth.openai.com/api/accounts/create_account",
                                json={"name": name, "birthdate": birthdate}, headers=headers)

    # ---- 步骤9 ----
    def step9_callback(self, auth_code: str, granted_scope: str):
        q = {"code": auth_code, "scope": granted_scope, "state": self.state.oauth_state}
        return self.engine.get("https://chatgpt.com/api/auth/callback/openai", params=q)

    # ---- 步骤10-11：登录态 prepare + finalize ----
    def step10_prepare(self):
        cfg = fake_config25(user_agent=self.state.user_agent, language=self.state.language,
                            languages=self.state.languages)
        body = build_sentinel_prepare_body(self.state, cfg)   # 实测仅 {p}（requirements token）
        return self.engine.post("https://chatgpt.com/backend-api/sentinel/chat-requirements/prepare",
                                json=body, headers=build_login_api_headers(self.state))

    def step11_finalize(self, prepare: dict):
        """实测 body 6.6-6.7KB：{prepare_token, proofofwork, turnstile}（records 11360）。
        proofofwork = solve_proofofwork；turnstile = solve_turnstile(dx, key) = generate_t（EXACT 验证）。"""
        body = {"prepare_token": prepare.get("prepare_token")}
        pw = self.state.sentinel_cache.get("proofofwork")
        if pw: body["proofofwork"] = pw
        ts = self.state.sentinel_cache.get("turnstile")
        if ts: body["turnstile"] = ts
        return self.engine.post("https://chatgpt.com/backend-api/sentinel/chat-requirements/finalize",
                                json=body, headers=build_login_api_headers(self.state))

    # ---- 步骤12 ----
    def step12_conversation_init(self):
        body = build_conversation_init_body(self.state)   # timezone/timezone_offset_min 确定性已验证
        return self.engine.post("https://chatgpt.com/backend-api/conversation/init",
                                json=body, headers=build_login_api_headers(self.state))

    # ---- 步骤13/14 ----
    def step13_sync_token(self):
        return self.engine.post("https://chatgpt.com/backend-api/bazaar/obi/sync-token",
                                json={"operation": "set", "obi": self.state.obi_token},
                                headers=build_login_api_headers(self.state))

    def run(self, email: str):
        self.state.login_hint = email
        self.state.auth_session_logging_id = new_logging_id()
        self.new_pkce()
        r1 = self.step1_authorize()            # 需先过 JSD 挑战（challenge_jsd 模块接入点）
        r2 = self.step2_sentinel("authorize_continue")
        self.state.sentinel_cache["authorize_continue"] = parse_sentinel_response(r2)
        r3 = self.step3_send_otp()
        otp = ""                                # 邮箱收码（外部接入）
        r5 = self.step5_validate_otp(otp)
        r7 = self.step7_create_account(name="", birthdate="")
        r9 = self.step9_callback(extract_code(r9_redirect(r7)), extract_scope(r7))
        r10 = self.step10_prepare()
        r11 = self.step11_finalize(parse_sentinel_response(r10))
        r12 = self.step12_conversation_init()
        r13 = self.step13_sync_token()
        return {"authorize": r1, "sentinel": r2, "otp_sent": r3, "validated": r5,
                "created": r7, "callback": r9, "prepared": r10, "finalized": r11,
                "init": r12, "sync": r13}


def extract_code(resp): ...
def extract_scope(resp): ...
def r9_redirect(resp): ...
