# 批量注册执行器：10 账号 × 4 区域（JP3/US3/ID2/IN2）
# 逐号顺序执行（每号独立进程：新鲜代理 sid / 新鲜引擎状态 / 号间人形间隔）
# 用法：python batch-register.py [起始索引]
import subprocess, sys, os, time, random, csv, pathlib, re

HERE = pathlib.Path(__file__).resolve().parent
PY = sys.executable
CSV_PATH = HERE / "registered-accounts.csv"
# 默认导出格式：accounts-clean.csv（一行一账号，upsert 合并）
CLEAN_PATH = HERE / "accounts-clean.csv"
CLEAN_HDR = ["email", "region", "proxy_sid", "gateway", "status", "profile", "exit_ip",
             "password", "totp_secret", "session_token_0", "session_token_1", "access_token",
             "notes", "last_update", "alive"]
STATUS_RANK = {"failed": 0, "success": 1, "login-success": 2, "mfa-success": 3, "harden-success": 4, "harden-failed": 0}


def clean_upsert(email, fields):
    """accounts-clean.csv upsert：同 email 合并（非空覆盖，状态取最高，last_update 刷新）"""
    rows = []
    if CLEAN_PATH.exists():
        try:
            with open(CLEAN_PATH, encoding="utf-8-sig") as f:
                rows = list(csv.DictReader(f))
        except Exception:
            rows = []
    merged = {r.get("email", ""): r for r in rows}
    m = merged.get(email, {h: "" for h in CLEAN_HDR})
    m["email"] = email
    for h in CLEAN_HDR:
        v = (fields.get(h) or "").strip() if isinstance(fields.get(h), str) else fields.get(h)
        if v:
            m[h] = v
    if STATUS_RANK.get(fields.get("status", ""), -1) >= STATUS_RANK.get(m.get("status", ""), -1):
        m["status"] = fields.get("status", m.get("status", ""))
    m["last_update"] = time.strftime("%Y-%m-%d %H:%M:%S")
    merged[email] = m
    with open(CLEAN_PATH, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=CLEAN_HDR)
        w.writeheader()
        for e in merged:
            w.writerow({h: (merged[e].get(h) or "") for h in CLEAN_HDR})

# —— 账号任务表（email, otp_hook, region）——分配：JP×3 US×3 ID×2 IN×2 ——
ACCOUNTS = [
    ("<EMAIL>", "<OTP_HOOK_URL>", "JP"),
    ("<EMAIL>", "<OTP_HOOK_URL>", "US"),
    ("<EMAIL>", "<OTP_HOOK_URL>", "ID"),
    ("<EMAIL>", "<OTP_HOOK_URL>", "IN"),
    ("<EMAIL>", "<OTP_HOOK_URL>", "JP"),
    ("<EMAIL>", "<OTP_HOOK_URL>", "US"),
    ("<EMAIL>", "<OTP_HOOK_URL>", "ID"),
    ("<EMAIL>", "<OTP_HOOK_URL>", "IN"),
    ("<EMAIL>", "<OTP_HOOK_URL>", "JP"),
    ("<EMAIL>", "<OTP_HOOK_URL>", "US"),
]

TRANSCRIPT_DIR = HERE / "batch-transcripts"
TRANSCRIPT_DIR.mkdir(exist_ok=True)


def mk_sid(region: str) -> str:
    """每号新鲜 sid（独立出口 IP）"""
    return "R" + "".join(random.choices("abcdefghjkmnpqrstuvwxyz23456789", k=9))


def csv_row(row: list):
    """12 列宽表（与 T4 csv_record 同 schema）"""
    HDR = ["timestamp", "email", "region", "proxy_sid", "gateway", "status", "profile",
           "exit_ip", "notes", "session_token_0", "session_token_1", "access_token"]
    exists = CSV_PATH.exists()
    with open(CSV_PATH, "a", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f)
        if not exists:
            w.writerow(HDR)
        w.writerow(row + [""] * (len(HDR) - len(row)))


def classify(out: str, code: int):
    """从 T4 输出判结果"""
    if "[CSV] success" in out:
        return "success", "callback 302 + session-token"
    if "session-token" in out and code == 0:
        return "success", "session-token 已下发"
    m = re.search(r"\[FATAL\]\s*(.{0,110})", out)
    if m:
        return "failed", m.group(1).strip()
    if code != 0:
        return "failed", f"exit={code}"
    return "unknown", "无 FATAL 无 session-token（复核 transcript）"


def main():
    start = int(sys.argv[1]) if len(sys.argv) > 1 else 0
    results = {}
    for idx, (email, hook, region) in enumerate(ACCOUNTS):
        if idx < start:
            continue
        sid = mk_sid(region)
        gw = os.environ.get("PROXY_HOST_SG", "<PROXY_HOST_SG>") if region in ("JP", "ID", "SG") else os.environ.get("PROXY_HOST_US", "<PROXY_HOST_US>")
        print(f"\n{'='*74}\n[{idx+1}/10] {email} region={region} sid={sid} gw={gw}\n{'='*74}", flush=True)
        t0 = time.strftime("%Y-%m-%d %H:%M:%S")
        r = subprocess.run(
            [PY, str(HERE / "live-test-t4.py"), email, hook, region, sid],
            capture_output=True, text=True, encoding="utf8", errors="replace", timeout=900)
        out = (r.stdout or "") + "\n" + (r.stderr or "")
        # 存独立 transcript
        (TRANSCRIPT_DIR / f"{idx+1:02d}-{email.split('@')[0]}-{region}.log").write_text(out, encoding="utf8")
        status, note = classify(out, r.returncode)
        # 提取出口 IP / profile（T4 前置探测行）
        ipm = re.search(r"\[PROBE\] exit-ip=([0-9.]+)", out)
        exit_ip = ipm.group(1) if ipm else ""
        pm = re.search(r"profile[=:\s]+([A-Za-z]+ [A-Z] /\d{4}-\d{2}-\d{2})", out)
        profile = pm.group(1) if pm else ""
        # T4 成功时已自记 CSV；这里只补失败/未知行
        if status != "success":
            csv_row([t0, email, region, sid, gw, status, profile, exit_ip, note[:220]])
        # 默认导出格式：accounts-clean.csv upsert（所有状态都记，成功行由 T5 链补密码/TOTP）
        clean_upsert(email, {
            "region": region, "proxy_sid": sid, "gateway": gw,
            "status": status, "profile": profile, "exit_ip": exit_ip,
            "notes": note[:220],
        })
        results[email] = (status, note)
        print(f"[{idx+1}/10] => {status}: {note[:110]}", flush=True)
        # 号间人形间隔（末号不等）
        if idx < len(ACCOUNTS) - 1 and idx + 1 >= start:
            gap = random.uniform(35, 95)
            print(f"[gap] 下一号前等待 {gap:.0f}s …", flush=True)
            time.sleep(gap)
    print("\n===== 批量结果汇总 =====")
    ok = sum(1 for s, _ in results.values() if s == "success")
    print(f"成功 {ok}/{len(results)}")
    for email, (s, n) in results.items():
        print(f"  {s:8s} {email}  ({n[:70]})")
    print(f"CSV: {CSV_PATH}")


if __name__ == "__main__":
    main()
