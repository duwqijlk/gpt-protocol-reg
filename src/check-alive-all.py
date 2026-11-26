"""全量深度存活：11 账号 × me + conversations + models 三连，输出可用性表"""
import sys, json, pathlib, random, time
sys.path.insert(0, r"C:\Users\Administrator\Desktop\GPT新版本协议研究")
from live_engine import LiveEngine, proxy_url

P = pathlib.Path(r"C:\Users\Administrator\Desktop\GPT新版本协议研究\build\tokens")
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36"
BASE = {"User-Agent": UA, "accept-language": "en-US,en;q=0.9", "Accept": "*/*"}

rows = []
for f in sorted(P.glob("*.json")):
    d = json.loads(f.read_text(encoding="utf8"))
    email = d.get("email", f.stem)
    at = d.get("access_token") or ""
    if not at:
        rows.append((email, "NO_TOKEN", "-", "-", "-", "-"))
        continue
    eng = LiveEngine(proxy=proxy_url(d.get("region", "JP"),
                                     "Lv" + "".join(random.choices("abcdefghjkmnpqrstuvwxyz23456789", k=8)),
                                     host_tpl="<PROXY_HOST>"))
    H = dict(BASE, Authorization="Bearer " + at, Referer="https://chatgpt.com/")
    try:
        r1 = eng.get("https://chatgpt.com/backend-api/me", headers=H)
        me = json.loads(r1.body.decode("utf-8", "replace")) if r1.status == 200 else {}
        r2 = eng.get("https://chatgpt.com/backend-api/conversations?offset=0&limit=1", headers=H)
        r3 = eng.get("https://chatgpt.com/backend-api/models", headers=H)
        n_models = 0
        try:
            n_models = len(json.loads(r3.body.decode("utf-8", "replace")).get("models", []))
        except Exception:
            pass
        verdict = "ALIVE" if (r1.status == 200 and me.get("email")) else ("BANNED?" if r1.status in (403, 401) else f"HTTP{r1.status}")
        rows.append((email, verdict, me.get("id", "-"), me.get("country", "-"),
                     f"conv{r2.status}", f"models={n_models}"))
    except Exception as e:
        rows.append((email, "ERROR", "-", "-", "-", str(e)[:30]))
    time.sleep(1.0)

print(f"{'email':<38}{'verdict':<10}{'country':<9}{'conv':<8}{'models':<10}")
for r in rows:
    print(f"{r[0]:<38}{r[1]:<10}{r[3]:<9}{r[4]:<8}{r[5]:<10}")

alive = sum(1 for r in rows if r[1] == "ALIVE")
print(f"\n=== 可用 {alive}/{len(rows)}")
