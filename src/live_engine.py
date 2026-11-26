# LiveEngine：curl_cffi (Chrome 指纹) + 区域代理，供实测联调
# 接口对齐 build/tls_engine.HttpEngine
# 反识别修复清单：
#   ① 版本对齐（impersonate 目标 = UA 声明版本）
#   ② 连接复用（curl_cffi.Session 持久化，模拟浏览器一连接多请求 + 会话恢复）
#   ③ 域作用域 cookie jar（按 Set-Cookie 的 Domain 存取，绝不错发到别的域）
#   ④ 请求类型化头（导航=完整 Accept+Sec-Fetch-Dest:document；fetch=Sec-Fetch-Dest:empty 等）
#   ⑤ 人形节奏（step_sleep 抖动助手）
from __future__ import annotations
import time, json as _json, random, urllib.parse as _up
try:
    from .tls_engine import HttpResponse, HttpEngine
except ImportError:
    from tls_engine import HttpResponse, HttpEngine

from curl_cffi.requests import Session as CffiSession


# ---- ④ Chrome 真实请求类型头（150 实测矩阵，08-headers.md） ----
NAV_ACCEPT = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"
NAV_ACCEPT_ENCODING = "gzip, deflate, br, z"


def navigation_headers(extra: dict | None = None, *, for_url: str = "",
                       init_url: str = "", referer: str = "") -> dict:
    """顶层导航（authorize/callback/页面跳转）用的完整 Chrome 头组。
    for_url=请求 URL；init_url=发起上下文源（如 chatgpt.com 页）→ 算 Sec-Fetch-Site。"""
    site = "none" if not init_url else sec_fetch_site_for(for_url, init_url)
    h = {
        "Accept": NAV_ACCEPT,
        "Accept-Encoding": NAV_ACCEPT_ENCODING,
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": site,
        "Sec-Fetch-User": "?1",
        "Upgrade-Insecure-Requests": "1",
    }
    if referer:
        h["Referer"] = referer
    if extra:
        h.update(extra)
    return h


def fetch_headers(extra: dict | None = None, *, for_url: str = "",
                  init_url: str = "", referer: str = "", origin: str = "",
                  content_type: str | None = "application/json") -> dict:
    """XHR/fetch（API POST/GET）用的 Chrome 头组。
    for_url=请求 URL；init_url=页面源 → Sec-Fetch-Site；origin=请求 Origin。"""
    site = "same-origin" if not init_url else sec_fetch_site_for(for_url, init_url)
    h = {
        "Accept": "*/*",
        "Accept-Encoding": NAV_ACCEPT_ENCODING,
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": site,
        "Priority": "u=1, i",
    }
    if content_type:
        h["Content-Type"] = content_type
    if referer:
        h["Referer"] = referer
    if origin:
        h["Origin"] = origin
    if extra:
        h.update(extra)
    return h


def _site(url: str) -> str:
    return "same-origin"


def _site(url: str) -> str:
    try:
        p = _up.urlparse(url)
        return f"same-origin" if not p.scheme else f"{p.scheme}"
    except Exception:
        return "same-origin"


def sec_fetch_site_for(req_url: str, init_url: str) -> str:
    """按请求 URL 与发起源算 Sec-Fetch-Site（cross-site / same-origin / same-site）。"""
    try:
        a = _up.urlparse(req_url)
        b = _up.urlparse(init_url)
        if a.netloc == b.netloc:
            return "same-origin"
        if a.hostname.rsplit(".", 2)[-2:] == b.hostname.rsplit(".", 2)[-2:]:
            return "same-site"
        return "cross-site"
    except Exception:
        return "cross-site"


class DomainCookieJar:
    """③ 域作用域 cookie：解析 Set-Cookie 的 Domain 属性，只在匹配域上发送（浏览器语义）。"""

    def __init__(self):
        self._d = {}   # (host_tail, name) -> (value, attrs)

    def absorb(self, resp_headers: dict, req_host: str):
        # curl_cffi 的 r.cookies 缺 domain 信息，直接吃原始 set-cookie 头
        pairs = []
        for k, v in (resp_headers or {}).items():
            if k.lower() == "set-cookie":
                pairs.extend(v if isinstance(v, list) else [v])
        for raw in pairs:
            if not raw or ";" not in raw and "=" not in raw:
                continue
            parts = raw.split(";")
            nv = parts[0].strip()
            if "=" not in nv:
                continue
            name, val = nv.split("=", 1)
            domain = req_host
            for attr in parts[1:]:
                attr = attr.strip()
                if attr.lower().startswith("domain="):
                    domain = attr.split("=", 1)[1].strip().lstrip(".")
            host_tail = domain.lower()
            self._d[(host_tail, name.strip())] = (val, raw)

    def header_for(self, url: str) -> str:
        """只发与该 host 匹配的 cookie（host 尾匹配，含 Domain=.openai.com 泛域）。"""
        host = _up.urlparse(url).hostname or ""
        host = (host or "").lower()
        out = []
        for (tail, name), (val, _raw) in self._d.items():
            if host == tail or host.endswith("." + tail):
                out.append(f"{name}={val}")
        return "; ".join(out)

    def names(self):
        return sorted({n for (_t, n) in self._d})


class LiveEngine(HttpEngine):
    """curl_cffi impersonate=chrome（真实 Chrome TLS/HTTP2 指纹）+ HTTP 代理（区域出口）。
    版本对齐：impersonate 目标版本必须与 UA 声明版本一致（如 UA=150 → impersonate="chrome150"），
    否则 TLS ClientHello（JA4）与 UA 版本号错位，是被动指纹交叉核对的一眼假信号。"""

    # 声明 UA 版本 → curl_cffi 支持的 impersonate 目标（0.17.0 实测支持到 chrome152）
    IMPERSONATE_BY_UA = {
        "149": "chrome150",   # 149 无独立目标，用最近的 150（ClientHello 差异极小）
        "150": "chrome150",
        "151": "chrome151",
        "152": "chrome152",
    }

    def __init__(self, proxy: str | None = None, impersonate: str = "chrome150",
                 timeout: float = 30.0, cookie_jar: dict | None = None):
        # proxy 形如 http://user:pass@host:port
        self.proxy = proxy
        self.impersonate = impersonate
        self.timeout = timeout
        self.cookies = cookie_jar or {}
        self.jar = DomainCookieJar()
        # ② 持久会话：连接复用 + TLS 会话恢复（浏览器语义）
        proxies = {"http": self.proxy, "https": self.proxy} if self.proxy else None
        self.session = CffiSession(impersonate=self.impersonate,
                                   timeout=self.timeout, proxies=proxies,
                                   allow_redirects=False)

    def _kw(self, headers: dict | None, extra: dict | None = None):
        kw = {"impersonate": self.impersonate, "timeout": self.timeout,
              "allow_redirects": False}
        if headers:
            kw["headers"] = headers
        if extra:
            kw.update(extra)
        return kw

    def get(self, url, params=None, headers=None) -> HttpResponse:
        t0 = time.monotonic()
        hd = dict(headers or {})
        ck = self.jar.header_for(url)
        if ck:
            hd["Cookie"] = ck
        r = self.session.get(url, params=params, **self._kw(hd))
        self.jar.absorb(dict(r.headers), _up.urlparse(url).hostname or "")
        return HttpResponse(status=r.status_code, headers=dict(r.headers),
                            body=r.content, url=str(r.url),
                            elapsed_ms=(time.monotonic() - t0) * 1000)

    def post(self, url, json=None, data=None, headers=None) -> HttpResponse:
        t0 = time.monotonic()
        hd = dict(headers or {})
        ck = self.jar.header_for(url)
        if ck:
            hd["Cookie"] = ck
        if json is not None:
            r = self.session.post(url, json=json, **self._kw(hd))
        elif data is not None:
            r = self.session.post(url, data=data, **self._kw(hd))
        else:
            # 空 body POST：绝不带 content-type（实测 API 拒绝 form 默认值）
            hd.pop("Content-Type", None)
            hd.pop("content-type", None)
            hd["Content-Length"] = "0"
            r = self.session.post(url, **self._kw(hd))
        self.jar.absorb(dict(r.headers), _up.urlparse(url).hostname or "")
        return HttpResponse(status=r.status_code, headers=dict(r.headers),
                            body=r.content, url=str(r.url),
                            elapsed_ms=(time.monotonic() - t0) * 1000)

    def _absorb(self, r):
        # 兼容旧调用（真实吸收在 jar.absorb）
        try:
            for k, v in r.cookies.items():
                self.cookies[k] = v
        except Exception:
            pass

    # ⑤ 人形节奏：阶段间 1.2~4.8s 对数正态抖动
    def human_pause(self, low: float = 1.2, high: float = 4.8):
        d = min(max(random.lognormvariate(0.35, 0.45), low), high)
        time.sleep(d)


def proxy_url(region: str, sid: str, user_prefix: str = None, password: str = None, host_tpl: str = None, ttl_min: int = 20):
    user_prefix = user_prefix or os.environ.get("PROXY_USER", "<PROXY_USER>")
    password = password or os.environ.get("PROXY_PASSWORD", "<PROXY_PASSWORD>")
    host_tpl = host_tpl or os.environ.get("PROXY_HOST", "<PROXY_HOST>")
    """按 BitBrowser 的代理用户名格式拼代理 URL（region: IN/US/ID/SG...）。"""
    user = f"{user_prefix}-region-{region}-sid-{sid}-t-{ttl_min}"
    return f"http://{user}:{password}@{host_tpl}:443"
