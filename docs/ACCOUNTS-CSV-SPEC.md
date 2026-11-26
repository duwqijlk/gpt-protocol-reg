# 账号表导出格式规范（注册机默认）

## 唯一标准：`build/accounts-clean.csv`

**格式**（用户指定，2026-11-26 起为注册机默认导出）：

```csv
email,region,proxy_sid,gateway,status,profile,exit_ip,password,totp_secret,
session_token_0,session_token_1,access_token,notes,last_update,alive,team_promo
```

- **一行一个账号**（不是追加式流水）
- 同 email 重跑 → **upsert 合并**：非空字段覆盖旧值、状态取最高（harden-success > mfa-success > login-success > success > failed）、last_update 刷新
- `password` 列只在 password/add 真正成功（200 + callback）才写入——未生效的生成密码绝不落表
- `alive` 列由巡检脚本（check-alive-all.py）维护
- `team_promo` 列由 t5-harden T5.11 步维护（team-1-month-free 促销资格：eligible / not_eligible）

## 写入方（已全部改造完成）

| 脚本 | 行为 |
|---|---|
| `t5-harden.py` | 收尾时 upsert 到 accounts-clean.csv（status/密码/TOTP/tokens/notes 全量）+ 继续追加 registered-accounts.csv 流水（调试痕迹） |
| `batch-register.py` | 每号跑完 upsert（region/sid/gateway/status/profile/exit_ip/notes）；密码和 TOTP 由后续 t5 链补全 |

## 验证

- `test-csv-upsert.py` — t5 收尾逻辑演练（11+1=12 行，老行零破坏）✅ 已通过
- batch-register 的 `clean_upsert()` 函数级演练 ✅ 已通过
- 两个文件语法检查 ✅

## 相关文件

- `build/accounts-clean.csv` — 唯一权威账号表
- `build/registered-accounts.csv` — 历史流水日志（只读保留，继续追加）
- `build/tokens/<email>.json` — 单账号完整凭据
- `build/clean-accounts.py` — 从流水重建账号表（历史数据迁移用）
- `build/check-alive-all.py` — 存活巡检（维护 alive 列）
