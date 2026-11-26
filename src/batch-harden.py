"""批量加固收尾：9 个无密码账号跑 t5（密码 + TOTP MFA 全套）
ashy 已有 TOTP（登录遇 mfa-challenge 路径），其余 8 个无 MFA（enroll 路径）
"""
import subprocess, sys, time, random, pathlib, json

HERE = pathlib.Path(__file__).resolve().parent
PY = sys.executable

ACCOUNTS = [
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

TDIR = HERE / "batch-transcripts"
TDIR.mkdir(exist_ok=True)


def main():
    skip = int(sys.argv[1]) if len(sys.argv) > 1 else 0
    ok_pw, ok_totp = 0, 0
    for idx, (email, hook, region) in enumerate(ACCOUNTS):
        if idx < skip:
            continue
        sid = "H" + "".join(random.choices("abcdefghjkmnpqrstuvwxyz23456789", k=9))
        print(f"\n[{idx+1}/{len(ACCOUNTS)}] {email} region={region} sid={sid}", flush=True)
        try:
            r = subprocess.run(
                [PY, str(HERE / "t5-harden.py"), email, hook, region, sid],
                capture_output=True, text=True, encoding="utf8", errors="replace", timeout=1500)
            out = (r.stdout or "") + (r.stderr or "")
            (TDIR / f"{idx+1:02d}-{email.split('@')[0]}-{region}-harden.log").write_text(out, encoding="utf8")
            pw = "password=✓" in out
            totp = "totp_secret=✓" in out
            ok_pw += 1 if pw else 0
            ok_totp += 1 if totp else 0
            # 提取密码和 TOTP
            for ln in out.splitlines():
                if ln.startswith("[DONE]"):
                    print("   " + ln[:150], flush=True)
                    break
            if not pw:
                # 失败时打尾部
                for ln in out.splitlines()[-6:]:
                    print("   | " + ln[:130], flush=True)
        except subprocess.TimeoutExpired:
            print("   TIMEOUT", flush=True)
        except Exception as e:
            print(f"   EXC {str(e)[:80]}", flush=True)
        time.sleep(30)  # send-otp 限流间隔
    print(f"\n=== 完成: password {ok_pw}/{len(ACCOUNTS)-skip} | totp {ok_totp}/{len(ACCOUNTS)-skip}")


if __name__ == "__main__":
    main()
