"""纯协议版长链脚本：不开浏览器，直接用账号的 access_token 跑资格检测
流程（对照 JS 脚本）：
  1) /api/auth/session → accessToken（我们已有 tokens/）
  2) /backend-api/me → 国家/货币
  3) check_coupon → 资格判定（JS 脚本在这停：state != eligible）
  4) （可选）创建 hosted checkout 长链——只有 eligible 才建
用法: python check-team-promo.py [email过滤词]
"""
import sys, json, pathlib, random, time
sys.path.insert(0, r"C:\Users\Administrator\Desktop\GPT新版本协议研究")
from build.live_engine import LiveEngine, proxy_url

P = pathlib.Path(r"C:\Users\Administrator\Desktop\GPT新版本协议研究\build\tokens")
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36"
BASE = {"User-Agent": UA, "accept-language": "en-US,en;q=0.9", "Accept": "*/*", "Referer": "https://chatgpt.com/"}
FX = {"US": "USD", "JP": "JPY", "GB": "GBP", "CA": "CAD", "AU": "AUD", "SG": "SGD", "ID": "IDR", "IN": "INR", "KR": "KRW", "HK": "HKD", "TW": "TWD", "DE": "EUR", "FR": "EUR"}

filt = (sys.argv[1] if len(sys.argv) > 1 else "").lower()
results = []
for f in sorted(P.glob("*.json")):
    d = json.loads(f.read_text(encoding="utf8"))
    email, at = d.get("email", ""), d.get("access_token") or ""
    if not at or (filt and filt not in email):
        continue
    eng = LiveEngine(proxy=proxy_url(d.get("region", "JP"),
                     "Pc" + "".join(random.choices("abcdefghjkmnpqrstuvwxyz23456789", k=8)),
                     host_tpl="<PROXY_HOST>"))
    H = dict(BASE, Authorization="Bearer " + at)
    try:
        # me（国家）
        r = eng.get("https://chatgpt.com/backend-api/me", headers=H)
        me = json.loads(r.body.decode("utf-8", "replace")) if r.status == 200 else {}
        country = (me.get("country") or "US").upper()
        # check_coupon（资格判定——JS 脚本第 3 步）
        r2 = eng.get("https://chatgpt.com/backend-api/promo_campaign/check_coupon?coupon=team-1-month-free&is_coupon_from_query_param=false", headers=H)
        cc = json.loads(r2.body.decode("utf-8", "replace")) if r2.status == 200 else {}
        state = cc.get("state", "?")
        results.append((email, country, state))
        print(f"{state:<14} {email:<38} {country}/{FX.get(country, '?')}")
        if state == "eligible":
            print(f"    ★ 满足条件！redemption: {json.dumps(cc.get('redemption'), ensure_ascii=False)[:150]}")
    except Exception as e:
        print(f"ERROR          {email:<38} {str(e)[:50]}")
    time.sleep(1.2)

elig = sum(1 for r in results if r[2] == "eligible")
print(f"\n=== 资格: {elig}/{len(results)}")
