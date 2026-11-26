"""ship 文件去重真发（跳过沙箱——直接用已产出的 POST）"""
import sys, os, re, json, pathlib, time, random, string
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from build.live_engine import LiveEngine, proxy_url

BUILD = pathlib.Path(__file__).resolve().parent
SHIP = BUILD / "params" / "cf-jsd-ship.json"
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36"
BASE = {"User-Agent": UA, "sec-ch-ua": '"Not;A=Brand";v="8", "Chromium";v="150", "Google Chrome";v="150"',
        "sec-ch-ua-mobile": "?0", "sec-ch-ua-platform": '"Windows"',
        "accept-language": "en-US,en;q=0.9"}

posts = json.loads(SHIP.read_text())
# 去重（按 URL + body 前 80）
seen = set()
uniq = []
for p in posts:
    k = p["u"] + (p["b"] or "")[:80]
    if k not in seen:
        seen.add(k)
        uniq.append(p)
print(f"去重后 {len(uniq)}/{len(posts)} 个 POST")

sid = "Jsdbg" + "".join(random.choices("abcdefghjkmnpqrstuvwxyz23456789", k=8))
eng = LiveEngine(proxy=proxy_url("US", sid, host_tpl="<PROXY_HOST>"))
for i, post in enumerate(uniq[:6]):
    u = post["u"]
    if not u.startswith("http"):
        u = "https://auth.openai.com" + u
    body = post["b"] or ""
    h = dict(BASE, **{"Accept": "*/*", "Referer": "https://auth.openai.com/",
                       "Origin": "https://auth.openai.com",
                       "Content-Type": "text/plain;charset=UTF-8"})
    try:
        rr = eng.post(u, data=body.encode("utf-8", "replace") if body else b"", headers=h)
        text = rr.body.decode("utf-8", "replace")[:160]
        setck = [v for k, v in (rr.headers or {}).items() if k.lower() == "set-cookie"]
        print(f"[{i}] {u[:105]}")
        print(f"    status={rr.status} body={text[:120]}")
        if setck:
            print(f"    set-cookie: {[s.split(';')[0][:70] for s in setck]}")
    except Exception as e:
        print(f"[{i}] EXC {str(e)[:90]}")
    time.sleep(1.0)
