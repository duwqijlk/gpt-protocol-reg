"""Node 转发层 Python 客户端：t5 的 reauth 请求经 Node fetch 发（同指纹）"""
import subprocess, json, threading, queue, os, pathlib

BUILD = pathlib.Path(__file__).resolve().parent
NODE = os.path.expandvars(r"%USERPROFILE%\.dsh\dsh-runtimes\dsh-primary-runtime\dependencies\node\bin\node.exe")


class NodeForwarder:
    def __init__(self):
        self.p = subprocess.Popen(
            [NODE, str(BUILD / "cf-jsd-forward.mjs")],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True, encoding="utf-8", errors="replace", bufsize=1)
        self.q = queue.Queue()
        self._id = 0
        threading.Thread(target=self._reader, daemon=True).start()

    def _reader(self):
        for line in self.p.stdout:
            line = line.strip()
            if line:
                try:
                    self.q.put(json.loads(line))
                except Exception:
                    pass

    def request(self, url, method="GET", headers=None, body=None, timeout=30):
        self._id += 1
        req = {"id": self._id, "url": url, "method": method, "headers": headers or {}}
        if body is not None:
            req["body"] = body
        self.p.stdin.write(json.dumps(req) + "\n")
        self.p.stdin.flush()
        # 等对应 id 的响应
        import time
        t0 = time.time()
        while time.time() - t0 < timeout:
            try:
                resp = self.q.get(timeout=1)
                if resp.get("id") == self._id:
                    return resp
            except queue.Empty:
                continue
        return {"id": self._id, "error": "timeout"}

    @property
    def jar(self):
        return getattr(self, "_jar", {})

    def close(self):
        try:
            self.p.stdin.close()
            self.p.terminate()
        except Exception:
            pass


if __name__ == "__main__":
    fwd = NodeForwarder()
    UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36"
    H = {"User-Agent": UA, "accept-language": "en-US,en;q=0.9",
         "Accept": "text/html,*/*;q=0.8", "Referer": "https://chatgpt.com/"}
    r = fwd.request("https://auth.openai.com/email-verification", headers=H)
    print(f"落页: {r.get('status')} err={r.get('error')}")
    print("jar:", {k: v[:28] for k, v in (r.get("jar") or {}).items()})
    fwd.close()
