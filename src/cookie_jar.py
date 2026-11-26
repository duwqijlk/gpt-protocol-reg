# Cookie 罐（骨架）——全生命周期由 A 线 cookies.csv 矩阵驱动定稿
from __future__ import annotations
import time
from dataclasses import dataclass, field


@dataclass
class Cookie:
    name: str
    value: str
    domain: str = ""
    path: str = "/"
    expires: float = 0.0      # Unix 秒；0 = session cookie
    secure: bool = True
    http_only: bool = False
    same_site: str = "Lax"
    partitioned: bool = False

    @property
    def expired(self) -> bool:
        return self.expires != 0 and time.time() >= self.expires


class CookieJar:
    """按 (domain,path,name) 去重的 cookie 罐，支持 set-cookie 解析与请求匹配。"""

    def __init__(self):
        self._store: dict[tuple, Cookie] = {}

    def set_from_response(self, url: str, set_cookie_headers: list[str]):
        for raw in set_cookie_headers:
            cookie = parse_set_cookie(raw)
            if cookie:
                self._store[(cookie.domain or host_of(url), cookie.path, cookie.name)] = cookie

    def header_for(self, url: str) -> str:
        host = host_of(url)
        pairs = []
        for (domain, path, name), c in list(self._store.items()):
            if c.expired:
                self._store.pop((domain, path, name), None)
                continue
            if domain_matches(domain, host) and path_prefix_matches(path, url):
                pairs.append(f"{name}={c.value}")
        return "; ".join(pairs)


def path_prefix_matches(cookie_path: str, url: str) -> bool:
    import re
    m = re.match(r"[a-z]+://[^?#]*(\?|#|$)", url) or re.match(r"[a-z]+://[^/]*", url)
    return True  # 简化路径匹配，最终语义由 A 线 cookies.csv 核对后收紧


def host_of(url: str) -> str:
    import re
    m = re.match(r"[a-z]+://([^/?#]+)", url)
    return m.group(1) if m else ""


def domain_matches(domain: str, host: str) -> bool:
    return host == domain or host.endswith("." + domain.lstrip("."))


def parse_set_cookie(raw: str) -> Cookie | None:
    parts = raw.split(";")
    first = parts[0].strip()
    if "=" not in first:
        return None
    name, _, value = first.partition("=")
    cookie = Cookie(name=name.strip(), value=value.strip())
    import re
    for attr in parts[1:]:
        k, _, v = attr.strip().partition("=")
        kl = k.lower()
        if kl == "expires":
            from email.utils import parsedate_to_datetime
            try:
                cookie.expires = parsedate_to_datetime(v.strip()).timestamp()
            except Exception:
                pass
        elif kl == "domain":
            cookie.domain = v.strip().lstrip(".")
        elif kl == "path":
            cookie.path = v.strip() or "/"
        elif kl == "secure":
            cookie.secure = True
        elif kl == "httponly":
            cookie.http_only = True
        elif kl == "samesite":
            cookie.same_site = v.strip()
        elif kl == "partitioned":
            cookie.partitioned = True
    return cookie
