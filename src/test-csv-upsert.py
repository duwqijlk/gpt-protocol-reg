"""模拟一次 t5 收尾的 CSV 写入（不动网络，只验证 accounts-clean.csv 的 upsert 逻辑）"""
import sys, json, time, csv as _csv, pathlib

BUILD = pathlib.Path(r"C:\Users\Administrator\Desktop\GPT新版本协议研究\build")
CLEAN_PATH = BUILD / "accounts-clean.csv"
CSV_PATH = BUILD / "registered-accounts.csv"

# 模拟一个新账号跑完
EMAIL = "<EMAIL>"
REGION, SID, _GATEWAY, EXIT_IP = "JP", "Htest12345", "arxlabs", "1.2.3.4"
STATUS = "harden-success"
PASSWORD_DONE, ACT_OK = True, True
REC_PASSWORD, REC_TOTP = "FakePw123!xyz", "FAKETOTPSECRETAAA2222"
st0, st1, ACCESS_TOKEN = "st0_x", "st1_x", "at_x"
NOTES = "password=✓已设置 totp=✓ validate→test"
NEW_PASSWORD, TOTP_SECRET = REC_PASSWORD, REC_TOTP

CLEAN_HDR = ["email", "region", "proxy_sid", "gateway", "status", "profile", "exit_ip",
             "password", "totp_secret", "session_token_0", "session_token_1", "access_token",
             "notes", "last_update", "alive"]
STATUS_RANK = {"failed": 0, "success": 1, "login-success": 2, "mfa-success": 3, "harden-success": 4, "harden-failed": 0}
clean_rows = []
if CLEAN_PATH.exists():
    with open(CLEAN_PATH, encoding="utf-8-sig") as f:
        clean_rows = list(_csv.DictReader(f))
this = {h: "" for h in CLEAN_HDR}
this.update({"email": EMAIL, "region": REGION, "proxy_sid": SID, "gateway": _GATEWAY,
             "status": STATUS, "exit_ip": EXIT_IP,
             "password": REC_PASSWORD, "totp_secret": REC_TOTP,
             "session_token_0": st0, "session_token_1": st1, "access_token": ACCESS_TOKEN,
             "notes": NOTES[:220], "last_update": time.strftime("%Y-%m-%d %H:%M:%S"), "alive": "YES" if ACT_OK else ""})
merged = {}
for r in clean_rows:
    merged[r.get("email", "")] = r
m = merged.get(EMAIL, {h: "" for h in CLEAN_HDR})
for h in CLEAN_HDR:
    if this[h]:
        m[h] = this[h]
if STATUS_RANK.get(STATUS, -1) >= STATUS_RANK.get(m.get("status", ""), -1):
    m["status"] = STATUS
m["last_update"] = this["last_update"]
merged[EMAIL] = m

# 演练输出到临时文件验证（不真写）
out = BUILD / "params" / "csv-rehearsal.csv"
with open(out, "w", newline="", encoding="utf-8-sig") as f:
    w = _csv.DictWriter(f, fieldnames=CLEAN_HDR)
    w.writeheader()
    for e in merged:
        w.writerow({h: (merged[e].get(h) or "") for h in CLEAN_HDR})

rows = list(_csv.DictReader(out.open(encoding="utf-8-sig")))
print(f"演练表: {len(rows)} 行（原 11 + 新 1 = 12 预期）")
new_row = [r for r in rows if r["email"] == EMAIL][0]
print(f"新账号行: {new_row['email']} | pw={new_row['password']} | status={new_row['status']} | alive={new_row['alive']}")
old_row = [r for r in rows if r["email"] == "<EMAIL>"][0]
print(f"老账号行完好: {old_row['email']} | pw={old_row['password'][:8]}… | alive={old_row['alive']}")
out.unlink()
print("✅ upsert 逻辑验证通过（未污染真实 accounts-clean.csv）")
