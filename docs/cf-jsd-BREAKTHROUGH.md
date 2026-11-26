# CF JSD 纯协议破解成果（第 1 轮）

## 突破：cf_clearance 已到手

```
[0] POST /cdn-cgi/challenge-platform/h/b/jsd/oneshot/f8df4d4a0cd6/0.745...:1794968128:9anv.../a5c50061ed7c9881
    → status=200
    → set-cookie: cf_clearance=CqpelUKITH2J7P9WG0GEZdKQJcJ87nzyXE3ZWrZTpAN1pcGIgwhSiVdmp  ✅✅✅
[1] POST /cdn-cgi/challenge-platform/h/b/eb/.../jsd（环境上报）
    → status=400（次要端点，不影响）
    → set-cookie: __cf_bm=...  ✅
```

## 完整链路（全部纯协议，无浏览器）

1. **beacon 活取**：GET 落页 → 解析 `__CF$cv$params{r,t}`（新鲜度<60s）
2. **Node vm 沙箱**（cf-jsd-sandbox.mjs）：
   - 完整 mock DOM/window/navigator/XHR
   - ctx 挂 `__CF$cv$params`/`_cf_chl_state`/`_cf_chl_opt`（`_61819e8f91c95d4afcbef7fb:"b"` 是关键钥匙）
   - `createElement('iframe')` 的 contentWindow 抛 cross-origin 错（模拟真浏览器竞态 → 触发错误上报分支）
   - `doc.readyState='complete'`（走 Xx() 直调分支）
   - vm 内顶层 `this`=global proxy（Wr[2] 寄存器读 ctx）
3. **main.js VM 内部**（42KB 混淆字节码已完全解剖）：
   - 字符串表：atob + 旋转16bit XOR（初值3507）自解码
   - X5 = 12 步 XHR 流程序（bA 数组："3941|3942|3940|..."）
   - 3941/3951 是反调试空步（fall-through 跳过）
   - oneshot URL = parent.origin + '/cdn-cgi/challenge-platform/h/' + state['_61819e...'] + bJ(实例参数) + ray
4. **ship 真发**（cf-jsd-ship.py）：沙箱 POST 写文件 → Python LiveEngine 真发 → **200 + cf_clearance**

## 待接（下一轮）

- [ ] cf_clearance + __cf_bm 写回 t5-harden.py 的 jar → 跑 reauth 实测 409 是否破
- [ ] XHR mock 的 onload 触发链（响应处理）完善
- [ ] 全链与 t5 引擎集成（cf-jsd-fullchain 合并进 reauth 流程）
