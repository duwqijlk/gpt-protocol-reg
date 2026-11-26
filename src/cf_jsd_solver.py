"""t5 前置：JSD 求解 → cf_clearance 写回引擎 jar 的模块
用法（在 t5-harden.py 的 reauth 前调用）：
  from build.cf_jsd_solver import solve_jsd
  clearance_cookies = solve_jsd(eng)   # 返回 {'cf_clearance': ..., '__cf_bm': ...}
  for k, v in clearance_cookies.items():
      eng.jar._d[("auth.openai.com", k)] = (v, "")
"""
import sys, os, re, pathlib, subprocess, random, string, json, time
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

BUILD = pathlib.Path(__file__).resolve().parent
NODE = os.path.expandvars(r"%USERPROFILE%\.dsh\dsh-runtimes\dsh-primary-runtime\dependencies\node\bin\node.exe")
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36"


def solve_jsd(eng, timeout_s=12):
    """在 eng 会话上解 CF JSD → 返回 {cookie名: 值}（含 cf_clearance）"""
    BASE = {"User-Agent": UA, "sec-ch-ua": '"Not;A=Brand";v="8", "Chromium";v="150", "Google Chrome";v="150"',
            "sec-ch-ua-mobile": "?0", "sec-ch-ua-platform": '"Windows"',
            "accept-language": "en-US,en;q=0.9"}

    # 1) 落页取 beacon（用现有引擎会话——cookie 一致）
    r = eng.get("https://auth.openai.com/email-verification",
                headers=dict(BASE, **{"Accept": "text/html,*/*;q=0.8", "Referer": "https://chatgpt.com/",
                                       "Sec-Fetch-Dest": "document", "Sec-Fetch-Mode": "navigate",
                                       "Sec-Fetch-Site": "cross-site", "Upgrade-Insecure-Requests": "1"}))
    body = r.body.decode("utf-8", "replace")
    m = re.search(r"window\.__CF\$cv\$params=\{r:'([0-9a-f]{16})',t:'([A-Za-z0-9+/=]+)'\}", body)
    if not m:
        return {}  # 无信标（可能已过 CF）——直接返回空
    ray, tb64 = m.group(1), m.group(2)
    age = int(time.time()) - int(__import__("base64").b64decode(tb64).decode())
    if age > 300:
        return {"_stale": ray}  # 信标过期

    # 2) 沙箱算 POST（ship 模式）
    ship_file = BUILD / "params" / "cf-jsd-ship.json"
    if ship_file.exists():
        ship_file.unlink()
    env = dict(os.environ, PYTHONIOENCODING="utf8", CF_JSD_SHIP=str(ship_file))
    sandbox = BUILD / "cf-jsd-sandbox.mjs"
    instr = BUILD / "params" / "cf-jsd-main-instr.js"
    if not instr.exists():
        instr = BUILD / "params" / "cf-jsd-main.js"
    p = subprocess.Popen([NODE, str(sandbox), str(instr), ray, tb64],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env)
    time.sleep(timeout_s)
    if p.poll() is None:
        p.kill()
    if not ship_file.exists():
        return {"_noship": ray}

    # 3) 去重 + 真发（oneshot 优先）
    posts = json.loads(ship_file.read_text())
    seen, uniq = set(), []
    for post in posts:
        k = post["u"] + (post["b"] or "")[:80]
        if k not in seen:
            seen.add(k)
            uniq.append(post)
    cookies = {}
    for post in uniq[:4]:
        u = post["u"]
        if not u.startswith("http"):
            u = "https://auth.openai.com" + u
        h = dict(BASE, **{"Accept": "*/*", "Referer": "https://auth.openai.com/",
                           "Origin": "https://auth.openai.com",
                           "Content-Type": "text/plain;charset=UTF-8"})
        try:
            rr = eng.post(u, data=(post["b"] or "").encode("utf-8", "replace"), headers=h)
            for k, v in (rr.headers or {}).items():
                if k.lower() == "set-cookie":
                    nv = v.split(";")[0]
                    if "=" in nv:
                        nm, val = nv.split("=", 1)
                        if nm in ("cf_clearance", "__cf_bm", "_cfuvid", "__cflb"):
                            cookies[nm] = val
        except Exception:
            pass
        time.sleep(0.8)
    return cookies


if __name__ == "__main__":
    from build.live_engine import LiveEngine, proxy_url
    sid = "Jsdbg" + "".join(random.choices("abcdefghjkmnpqrstuvwxyz23456789", k=8))
    eng = LiveEngine(proxy=proxy_url("US", sid, host_tpl="<PROXY_HOST>"))
    ck = solve_jsd(eng)
    print("结果:", json.dumps(ck, indent=1))
