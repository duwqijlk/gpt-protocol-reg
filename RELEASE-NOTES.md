# v1.0.0（2026-11-26）

首个开源版本。

## 核心特性

- OpenAI 账号全生命周期纯协议化：注册 / 登录 / reauth / MFA(TOTP) / 密码设置
- Cloudflare JSD 挑战纯协议求解（Node vm 沙箱 + oneshot 答案 + cf_clearance）
- Node fetch 转发层实现 TLS 指纹对齐（clearance 消费）
- 账号表 upsert 规范（accounts-clean.csv）
- 批量流水 + 存活巡检

## 已验证

- 11 账号注册→MFA→密码全链 11/11 成功
- 存活巡检 11/11（access_token 三连验证）
- 脱敏扫描零泄漏（代理 / OTP hook / 邮箱 / 密码 / TOTP / token 全替换）
