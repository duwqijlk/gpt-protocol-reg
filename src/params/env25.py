# config25 环境伪造器（01-proofofwork.md 下标 0-24 实测结构）
# 纯协议端生成与浏览器同构的 25 元数组；随机取样位（5/10/11/12）任选集合成员即可（服务端只验哈希前缀）
# 指纹一致性：时区/语言必须与出口 IP 地域一致（1031 IN 抓包 date 串=GMT+0530 India Standard Time）
from __future__ import annotations
import platform, random, time, uuid

# 区域预置：时区偏移串（config25[1] date 串）+ OAI-Language（抓包 IN=hi-IN, ID=id-ID, JP/US=en-US）
REGION_PRESETS = {
    "IN": {"tz_offset": "+0530", "tz_name": "India Standard Time", "language": "hi-IN", "languages": "hi-IN,en-US,en"},
    "US": {"tz_offset": "-0500", "tz_name": "Eastern Standard Time", "language": "en-US", "languages": "en-US,en"},
    "ID": {"tz_offset": "+0700", "tz_name": "Western Indonesia Time", "language": "id-ID", "languages": "id-ID,en-US,en"},
    "JP": {"tz_offset": "+0900", "tz_name": "Japan Standard Time", "language": "en-US", "languages": "en-US,en"},
}


def fake_config25(names: str = "", *, screen=(2560, 1440), user_agent: str = "",
                  language: str = "en-US", languages: str = "en-US,en",
                  hardware_concurrency: int = 8, build_tag: str = "c/20261117/_",
                  js_heap_size_limit: int | None = 2247024896,
                  tz_offset: str | None = None, tz_name: str | None = None) -> list:
    """下标语义（01 md）：
    0 屏幕宽高拼接 / 1 String(new Date) / 2 jsHeapSizeLimit / 3 尝试序号(求解时覆写)
    4 UA / 5 随机脚本派生串 / 6 build标签 / 7 语言 / 8 语言列表 / 9 耗时(求解时覆写)
    10 随机 navigator 原型键(注意 U+2212 真减号) / 11 随机 document 键 / 12 随机 window 键
    13 performance.now() / 14 uuid sid / 15 names / 16 硬件并发 / 17 timeOrigin
    18-24 window 特性探测位（ai/createPRNG/cache/data/solana/dump/InstallTrigger）"""
    now = time.localtime()
    # date 串时区 = 出口 IP 地域时区（指纹一致性硬要求）
    if tz_offset:
        date_str = time.strftime(f"%a %b %d %Y %H:%M:%S GMT{tz_offset} ({tz_name or ''})", now)
        if tz_name:
            date_str = time.strftime(f"%a %b %d %Y %H:%M:%S GMT{tz_offset} ({tz_name})", now)
        else:
            date_str = time.strftime(f"%a %b %d %Y %H:%M:%S GMT{tz_offset}", now)
    else:
        date_str = time.strftime("%a %b %d %Y %H:%M:%S GMT+0800 (China Standard Time)", now)
    nav_keys = ["userAgent−Mozilla/5.0", "language−" + language, "platform−Win32",
                "hardwareConcurrency−" + str(hardware_concurrency)]
    doc_keys = ["location", "querySelector", "body", "head", "title", "scripts", "cookie"]
    win_keys = ["location", "navigator", "document", "screen", "history", "localStorage",
                "performance", "crypto", "fetch", "WebSocket"]
    script_strs = [build_tag, "c/20261117/_", "app-runtime", "octane-shell"]
    return [
        f"{screen[0]}{screen[1]}",            # 0
        date_str,                              # 1
        js_heap_size_limit,                    # 2
        0,                                     # 3 ← 求解循环覆写为尝试序号
        user_agent or "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36",
        random.choice(script_strs),            # 5
        build_tag,                             # 6
        language,                              # 7
        languages,                             # 8
        0,                                     # 9 ← 求解循环覆写为耗时ms
        random.choice(nav_keys),               # 10
        random.choice(doc_keys),               # 11
        random.choice(win_keys),               # 12
        round(random.uniform(50, 3000), 2),    # 13
        str(uuid.uuid4()),                     # 14
        names,                                 # 15
        hardware_concurrency,                  # 16
        1794870000000,                         # 17 timeOrigin（会话起点毫秒）
        0, 0, 0, 0, 0, 0, 0,                   # 18-24 探测位（非Firefox/无solana等）
    ]


def region_config(region: str, names: str = "", *, user_agent: str = "",
                  screen=(2560, 1440), hardware_concurrency: int = 8) -> list:
    """按出口 IP 地域取整套一致的 language/tz 预置（与 OAI-Language 头、t 桩共用这张表）。"""
    p = REGION_PRESETS.get(region, REGION_PRESETS["US"])
    return fake_config25(names, screen=screen, user_agent=user_agent,
                         language=p["language"], languages=p["languages"],
                         hardware_concurrency=hardware_concurrency,
                         tz_offset=p["tz_offset"], tz_name=p["tz_name"])


def acquisition_names(query_keys: list[str]) -> str:
    """config[15] names：location.search 键序列 join(",")；
    白名单 {"q","m","query","prompt"}，最多 4 条（02 md acq-params 证据）。"""
    allowed = {"q", "m", "query", "prompt"}
    picked = [k for k in query_keys if k in allowed][:4]
    return ",".join(picked)
