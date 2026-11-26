"""批量检测协议注册账号是否存活
策略（由快到权威）：
  1) access_token (Bearer) → GET https://chatgpt.com/backend-api/me
  2) 失败则用 session_token → GET https://chatgpt.com/api/auth/session
  3) 再失败标记 dead/suspect
不消耗 OTP，不动密码。
"""
import sys, json, pathlib, random, string, time, base64, datetime
sys.path.insert(0, r"C:\Users\Administrator\Desktop\GPT新版本协议研究")
from build.live_engine import LiveEngine, proxy_url

P = pathlib.Path(r"C:\Users\Administrator\Desktop\GPT新版本协议研究\build\tokens")
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36"
BASE = {"User-Agent": UA, "accept-language": "en-US,en;q=0.9", "Accept": "*/*"}


def jwt_exp(tok):
    try:
        pl = tok.split(".")[1]
        pl += "=" * (-len(pl) % 4)
        return json.loads(base64.urlsafe_b64decode(pl)).get("exp")
    except Exception:
        return None


def new_engine(region):
    sid = "Lv" + "".join(random.choices("abcdefghjkmnpqrstuvwxyz23456789", k=8))
    return LiveEngine(proxy=proxy_url(region or "JP", sid, host_tpl="<PROXY_HOST>"))


results = []
for f in sorted(P.glob("*.json")):
    d = json.loads(f.read_text(encoding="utf8"))
    email = d.get("email", f.stem)
    at = d.get("access_token") or ""
    st0 = d.get("session_token_0") or ""
    region = d.get("region") or "JP"
    exp = jwt_exp(at)
    exp_s = datetime.datetime.fromtimestamp(exp, datetime.timezone.utc).strftime("%m-%d %H:%M") if exp else "?"

    verdict = "?"
    detail = ""
    eng = None
    try:
        eng = new_engine(region)
        # 1) access_token → backend-api/me
        if at:
            r = eng.get("https://chatgpt.com/backend-api/me",
                        headers=dict(BASE, Authorization="Bearer " + at,
                                     Referer="https://chatgpt.com/"))
            body = r.body.decode("utf-8", "replace")
            if r.status == 200 and '"email"' in body:
                try:
                    j = json.loads(body)
                    verdict = "ALIVE"
                    detail = f"me 200 | plan={j.get('plan_type') or j.get('plan') or '-'}"
                except Exception:
                    verdict = "ALIVE"
                    detail = "me 200"
            elif r.status in (401, 403):
                verdict = "TOKEN_DEAD"
                detail = f"me {r.status} → access_token 失效"
            else:
                verdict = "SUSPECT"
                detail = f"me {r.status} {body[:60]}"
        # 2) session token 兜底
        if verdict != "ALIVE" and st0:
            eng.jar._d[("chatgpt.com", "__Secure-next-auth.session-token")] = (st0, "")
            r2 = eng.get("https://chatgpt.com/api/auth/session",
                         headers=dict(BASE, Referer="https://chatgpt.com/"))
            b2 = r2.body.decode("utf-8", "replace")
            if "accessToken" in b2:
                verdict = "ALIVE"
                detail += " | session_token 有效"
            elif b2.strip() in ("{}", ""):
                detail += " | session_token 也空"
            else:
                detail += f" | session {r2.status}"
    except Exception as e:
        verdict = "ERROR"
        detail = str(e)[:70]

    results.append((email, verdict, detail, exp_s))
    print(f"{verdict:<11} {email:<38} exp={exp_s:<12} {detail[:70]}", flush=True)
    time.sleep(1.2)

alive = sum(1 for r in results if r[1] == "ALIVE")
print(f"\n=== 汇总: 存活 {alive}/{len(results)}")
print("\n存活账号:")
for email, v, detail, exp in results:
    if v == "ALIVE":
        print(f"  ✓ {email}")
print("\n需处理:")
for email, v, detail, exp in results:
    if v != "ALIVE":
        print(f"  ✗ {email}  [{v}] {detail[:60]}")

out = P.parent / "liveness-report.json"
out.write_text(json.dumps([{"email": e, "verdict": v, "detail": d, "at_exp": x} for e, v, d, x in results],
                          ensure_ascii=False, indent=1), encoding="utf8")
print(f"\n报告: {out}")
