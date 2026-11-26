"""beacon 参数提供器（stdout: ray tb64）"""
import sys, re, random, string
sys.path.insert(0, r"C:\Users\Administrator\Desktop\GPT新版本协议研究")
from build.live_engine import LiveEngine, proxy_url

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36"
for attempt in range(5):
    try:
        sid = "Jsfwd" + "".join(random.choices("abcdefghjkmnpqrstuvwxyz23456789", k=8))
        eng = LiveEngine(proxy=proxy_url("US", sid, host_tpl="<PROXY_HOST>"))
        r = eng.get("https://auth.openai.com/email-verification",
                    headers={"User-Agent": UA, "accept-language": "en-US,en;q=0.9", "Referer": "https://chatgpt.com/"})
        m = re.search(r"window\.__CF\$cv\$params=\{r:'([0-9a-f]{16})',t:'([A-Za-z0-9+/=]+)'\}", r.body.decode("utf-8", "replace"))
        if m:
            print(m.group(1), m.group(2), flush=True)
            sys.exit(0)
    except Exception:
        pass
print("FAIL", flush=True)
sys.exit(1)
