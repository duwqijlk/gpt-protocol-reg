# gpt-protocol-reg

OpenAI（chatgpt.com / auth.openai.com）账号的**纯协议**注册、登录、MFA(TOTP) 加固与密码设置工具链。
全程不依赖浏览器渲染——TLS 指纹伪装（curl_cffi）、Cloudflare JSD 挑战求解（Node vm 沙箱）、
sentinel/dx 反爬令牌合成均以纯协议实现。

## 交流群

有问题、经验分享、羊毛信息交流欢迎进群：

**[AI羊毛交流群](https://t.me/muihbb)** · t.me/muihbb

## 能力总览

| 链路 | 模块 | 说明 |
|---|---|---|
| 协议引擎 | `src/live_engine.py` | curl_cffi chrome150 指纹 + cookie jar |
| 注册+登录 | `src/live-test-t4.py` 流程（并入 t5-harden） | csrf → authorize → send-otp → validate → callback |
| JSD 挑战 | `src/cf_jsd_solver.py` + `tools/cf-jsd-sandbox.mjs` | CF `jsd/main.js` 字节码在 Node vm 沙箱求解 → oneshot POST → `cf_clearance` |
| 指纹对齐 | `src/node_forwarder.py` + `tools/cf-jsd-forward.mjs` | Node fetch 转发层，消费 clearance 的请求与解题连接同 JA3 |
| MFA 加固 | `src/t5-harden.py` | TOTP enroll + activate + password/add 全协议 |
| 批量 | `src/batch-register.py` / `batch-harden.py` | 多账号顺序流水（人形节奏） |
| 巡检 | `src/check-alive-all.py` | access_token → /backend-api/me 三连验活 |
| 促销资格 | `src/check-team-promo.py` / t5 T5.11 | team-1-month-free 优惠券资格检测（纯协议） |
| 账号表 | `src/accounts-clean` 格式 | 一行一账号，upsert 合并（见 docs/ACCOUNTS-CSV-SPEC.md） |

## 快速开始

```bash
# 1) 依赖
pip install curl_cffi pyotp

# 2) 配置
cp config.example.json config.json   # 填你的代理 / OTP hook

# 3) 单账号全链（注册→登录→MFA→密码）
python src/t5-harden.py <email> <otp_hook_url> <region> <sid>

# 4) 存活巡检
python src/check-alive-all.py

# 5) 账号表
python src/clean-accounts.py
```

## 目录

```
src/    协议链路核心（engine / solver / forwarder / t5 / batch / 巡检）
tools/  JSD 沙箱与转发器（Node）
docs/   技术文档（JSD 破解记录 / 账号表规范 / 抓包规范）
```

## 环境变量

| 变量 | 用途 |
|---|---|
| `PROXY_USER` / `PROXY_PASSWORD` / `PROXY_HOST` | 住宅代理凭据 |
| `OTP_HOOK_URL` | OTP 邮件取码回调 |
| `T5_OLD_PASSWORD` | reauth 场景的旧密码（改密用） |

## 技术要点

- **CF JSD 纯协议求解**：把 `jsd/main.js`（42KB 混淆 VM）放进 Node vm 沙箱，mock DOM/iframe 竞态触发错误上报分支，产出 oneshot POST 答案；`cf_clearance` 与 TLS 指纹绑定，消费端经 Node fetch 转发层保持同 JA3。详见 `docs/cf-jsd-BREAKTHROUGH.md`。
- **reauth 409 根因**：不是限流，是 authorize 被 CF 指纹拦截后会话作废。登录与 reauth 两个 authorize 都走 Node 转发后全链稳定。
- **产出格式**：`accounts-clean.csv` 一行一账号 upsert（规范见 docs/）。

## 免责声明

本项目仅用于安全研究与授权测试。使用者需自行遵守目标服务的条款与当地法规。

## License

MIT
