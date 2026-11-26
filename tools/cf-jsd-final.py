"""CF JSD 最终交付链 v3：
1. 活取 beacon(r,t)
2. 喂 Node 沙箱（ship 模式：POST 写文件）
3. Python 引擎读 ship 文件 → 用 LiveEngine 真发 oneshot POST
4. 验证返回 + cookie（__cf_bm 等）
"""
import sys, os, re, pathlib, subprocess, random, string, json, time
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from build.live_engine import LiveEngine, proxy_url

BUILD = pathlib.Path(__file__).resolve().parent
NODE = os.path.expandvars(r"%USERPROFILE%\.dsh\dsh-runtimes\dsh-primary-runtime\dependencies\node\bin\node.exe")
SHIP = BUILD / "params" / "cf-jsd-ship.json"
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36"
BASE = {"User-Agent": UA, "sec-ch-ua": '"Not;A=Brand";v="8", "Chromium";v="150", "Google Chrome";v="150"',
        "sec-ch-ua-mobile": "?0", "sec-ch-ua-platform": '"Windows"',
        "accept-language": "en-US,en;q=0.9"}

eng = None
ray = tb64 = None
for attempt in range(6):
    try:
        sid = "Jsdbg" + "".join(random.choices("abcdefghjkmnpqrstuvwxyz23456789", k=8))
        eng = LiveEngine(proxy=proxy_url("US", sid, host_tpl="<PROXY_HOST>"))
        r = eng.get("https://auth.openai.com/email-verification",
                    headers=dict(BASE, **{"Accept": "text/html,*/*;q=0.8", "Referer": "https://chatgpt.com/",
                                           "Sec-Fetch-Dest": "document", "Sec-Fetch-Mode": "navigate",
                                           "Sec-Fetch-Site": "cross-site", "Upgrade-Insecure-Requests": "1"}))
        body = r.body.decode("utf-8", "replace")
        m = re.search(r"window\.__CF\$cv\$params=\{r:'([0-9a-f]{16})',t:'([A-Za-z0-9+/=]+)'\}", body)
        if m:
            ray, tb64 = m.group(1), m.group(2)
            break
        eng = None
    except Exception as e:
        print(f"重试{attempt}: {str(e)[:60]}")
if not ray:
    print("beacon 获取失败")
    sys.exit(1)
age = int(time.time()) - int(__import__("base64").b64decode(tb64).decode())
print(f"ray={ray} 龄{age}s")

# ship 文件清空
if SHIP.exists():
    SHIP.unlink()

env = dict(os.environ, PYTHONIOENCODING="utf8", CF_JSD_SHIP=str(SHIP))
p = subprocess.Popen([NODE, str(BUILD / "cf-jsd-sandbox.mjs"), str(BUILD / "params" / "cf-jsd-main-instr.js"), ray, tb64],
                     stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env)
import threading
buf = []
def reader():
    for ln in p.stdout:
        buf.append(ln.decode("utf-8", "replace").rstrip())
threading.Thread(target=reader, daemon=True).start()
time.sleep(10)
if p.poll() is None:
    p.kill()
time.sleep(0.5)

if not SHIP.exists():
    print("!! 沙箱没产出 POST")
    for l in buf[-10:]:
        print("  " + l[:140])
    sys.exit(1)

posts = json.loads(SHIP.read_text())
print(f"\n=== 沙箱产出 {len(posts)} 个 POST，真发：")
for i, post in enumerate(posts):
    u = post["u"]
    if not u.startswith("http"):
        u = "https://auth.openai.com" + u
    body = post["b"] or ""
    h = dict(BASE, **{"Accept": "*/*", "Referer": "https://auth.openai.com/",
                       "Origin": "https://auth.openai.com",
                       "Content-Type": "text/plain;charset=UTF-8"})
    try:
        rr = eng.post(u, data=body.encode("utf-8", "replace") if body else b"", headers=h)
        text = rr.body.decode("utf-8", "replace")[:200]
        setck = [v for k, v in (rr.headers or {}).items() if k.lower() == "set-cookie"]
        print(f"[{i}] {post['m']} {u[:110]}")
        print(f"    → status={rr.status} body[:120]={text[:120]}")
        if setck:
            print(f"    → set-cookie: {[s.split(';')[0][:60] for s in setck]}")
    except Exception as e:
        print(f"[{i}] 发送异常: {str(e)[:100]}")
    time.sleep(1.2)
