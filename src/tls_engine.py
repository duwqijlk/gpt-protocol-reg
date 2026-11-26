# TLS/HTTP 指纹抽象层（骨架）
# 目标：HTTP2/TLS 指纹与 Chrome 一致（协议端不被指纹识别）。
# 实测浏览器：Chrome 150（BitBrowser coreVersion 150, UA 149 字符串，见 websocket 握手记录）。
# 实现策略（待定稿）：
#   1. 首选 curl_cffi impersonate="chromeXXX"（需确认 bundled Python 可装/已装）
#   2. 备选 Node undici + 自定义 ALPN/设置（限制多）
#   3. 兜底 http.client（仅离线回放验证用，不可用于实战）
# 接口约定与 analyze 阶段对齐：所有响应按 hop 记录，便于 verify/ 回放比对。
from __future__ import annotations
from dataclasses import dataclass, field


@dataclass
class HttpResponse:
    status: int
    headers: dict
    body: bytes
    url: str
    elapsed_ms: float = 0.0


class HttpEngine:
    """HTTP 引擎接口。子类实现真实指纹层；ReplayEngine 用于离线验证。"""

    def get(self, url: str, params: dict | None = None, headers: dict | None = None) -> HttpResponse:
        raise NotImplementedError

    def post(self, url: str, json: dict | None = None, data=None,
             headers: dict | None = None) -> HttpResponse:
        raise NotImplementedError

    # ---- 指纹要求（对照四 run 实测请求头矩阵，A 线产出后逐项核对） ----
    FINGERPRINT_REQUIREMENTS = {
        "http_version": "h2",
        "alpn": ["h2", "http/1.1"],
        "header_order": "chrome-150 标准序（待 A 线矩阵精确化）",
        "sec_ch_ua": '"Chromium";v="149", "Not?A_Brand";v="24"',  # 实测 UA 149
        "sec_ch_ua_platform": '"Windows NT 10.0; Win64; x64"',
        "accept_language": "en-US,en;q=0.9",   # 实测（websocket 握手记录）
    }


class ReplayEngine(HttpEngine):
    """离线回放引擎：从四 run 抓包读请求/响应，驱动 client.py 做逐字段比对（verify/ 阶段用）。"""

    def __init__(self, records_dirs: list[str]):
        self.records_dirs = records_dirs
        self.hops = []          # (request, response) 序列，按 walltime
        self._cursor = 0

    def get(self, url, params=None, headers=None):
        return self._next("GET", url)

    def post(self, url, json=None, data=None, headers=None):
        return self._next("POST", url)

    def _next(self, method, url):
        # 占位：加载 records.jsonl 按 (method, url 前缀) 匹配下一 hop
        raise NotImplementedError("待 A 线索引产物落地后实现精确匹配")
