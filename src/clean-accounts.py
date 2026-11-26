"""把 registered-accounts.csv（追加式日志，76 行）整理成 11 行干净账号表
规则：每账号一行，按时间顺序合并，非空字段取最新值；状态取最高阶段
"""
import csv, pathlib, collections

SRC = pathlib.Path(r"C:\Users\Administrator\Desktop\GPT新版本协议研究\build\registered-accounts.csv")
OUT = SRC.with_name("accounts-clean.csv")

RANK = {"success": 1, "login-success": 2, "mfa-success": 3, "harden-success": 4, "failed": 0}
FIELDS = ["email", "region", "proxy_sid", "gateway", "status", "profile", "exit_ip",
          "password", "totp_secret", "session_token_0", "session_token_1", "access_token",
          "notes", "last_update"]

rows = list(csv.DictReader(SRC.open(encoding="utf-8-sig")))
merged = collections.OrderedDict()

for r in rows:
    email = (r.get("email") or "").strip()
    if not email:
        continue
    m = merged.setdefault(email, {f: "" for f in FIELDS})
    for f in FIELDS:
        if f in ("status", "last_update"):
            continue
        v = (r.get(f) or "").strip()
        if v:
            m[f] = v  # 后出现的非空值覆盖（时间递增，即取最新）
    st = (r.get("status") or "").strip()
    if RANK.get(st, -1) >= RANK.get(m.get("status", ""), -1):
        m["status"] = st
    ts = (r.get("timestamp") or "").strip()
    if ts:
        m["last_update"] = ts

with OUT.open("w", newline="", encoding="utf-8-sig") as f:
    w = csv.DictWriter(f, fieldnames=FIELDS)
    w.writeheader()
    for email, m in merged.items():
        m["email"] = email
        w.writerow(m)

print(f"原始 {len(rows)} 行 → 整理后 {len(merged)} 行")
print(f"输出: {OUT}")
print(f"\n{'email':<38}{'status':<16}{'pw':<4}{'totp':<5}region")
for email, m in merged.items():
    print(f"{email:<38}{m['status']:<16}{'✓' if m['password'] else '-':<4}"
          f"{'✓' if m['totp_secret'] else '-':<5}{m['region']}")
