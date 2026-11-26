# 最终修复验证报告（全链收口）

## 冒烟测试（修复后实跑）

```
[T5.1] authorize(Node): status=302      ← 修复前 curl_cffi 经常 403
[T5.2] send-otp: status=200             ← 修复前 409 invalid_state
[T5.5b] reauth resend: status=200       ← 修复前 409
[T5.5r] mfa/verify: 200 → reset-password
[T5.7] session: accessToken ✓
```

## 已修复项

| 问题 | 根因 | 修复 |
|---|---|---|
| authorize 403 "Just a moment" | curl_cffi JA3 过不了 CF JSD 验证 | T5.1 登录 authorize 改走 Node 转发（与 JSD 同指纹） |
| send-otp 409 invalid_state | 403 后会话已废（非限流） | 同上——authorize 恢复 302 后 send-otp 200 |
| reauth resend 409 | 同根因（会话在 CF 层被掐） | reauth authorize 走 Node 转发（早前已修） |
| 35.snows reset 400 | 业务错（already-have-password），非会话错 | 无需修——该号已有密码 |
| send-otp 429（偶发） | 真限流（频率冷却） | 批量脚本已加 30-50s 间隔 |

## 账号终态：11/11 全套（密码+TOTP）

- 10 个纯协议设置（barkers/ashy/andante/amity/amazing/allele/adverbs/99-phonics/97.gyro/48vagrant）
- 35.snows 密码为窗口流程实设（<PASSWORD>），TOTP 纯协议
- 凭据双落档：build/tokens/*.json + registered-accounts.csv

## 唯一已知边界（非 bug）

已有密码的账号 reauth 后走 `password/reset` 会报 400 already-have-password——
这是 OpenAI 业务规则（改密需带旧密码或走 settings 流程），与链路无关。
新号（无密码）一律走 add 分支全通。
