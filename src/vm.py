# Sentinel 页内迷你 VM 解释器（纯协议复刻）
# 证据：analysis/protocol/js-algorithms/03-turnstile-dx-vm.md（操作码全表 0-35，三份拷贝一致）
# dx = base64( XOR_stream( JSON 指令表, key ) )；队列式执行；超时 turnstile 500ms → btoa(计数)
# 槽位：9=指令队列 3=resolve 4=reject 16=XOR key 10=window注入 12=寄存器表自引用
from __future__ import annotations
import base64, json, time, collections


def xor_stream(data: str, key: str) -> str:
    """h=(e,t)=> 循环键 XOR（repeating-key）"""
    if not key:
        return data
    out = []
    for i, ch in enumerate(data):
        out.append(chr(ord(ch) ^ ord(key[i % len(key)])))
    return "".join(out)


def decode_dx(dx: str, key: str) -> list:
    """dx → JSON 指令表。dx 里 ^ 处的字符偶有 URL 变体（-/_），按标准+URL 兼容处理。"""
    raw = base64.b64decode(dx.replace("-", "+").replace("_", "/") + "=" * ((-len(dx)) % 4))
    text = raw.decode("utf-8", errors="strict")
    return json.loads(xor_stream(text, key))


def b64u(s: str) -> str:
    return base64.b64encode(s.encode()).decode()


class VMFunction:
    """op30 定义的闭包：调用时绑定参数槽→切队列到程序→跑完取 ret_slot 值→恢复（JS y(e,t,r,n) 语义）"""

    def __init__(self, vm, ret_slot, params, prog):
        self.vm, self.ret_slot, self.params, self.prog = vm, ret_slot, params, prog

    def __call__(self, *args):
        vm, g = self.vm, self.vm.g
        saved = g[9]
        try:
            for slot, val in zip(self.params, args):
                g[slot] = val
            g[9] = list(self.prog)
            while g[9]:
                if (time.monotonic() - vm._t0) * 1000 > vm.timeout_ms:
                    return None
                ins = vm._shift(g[9])
                fn = g.get(ins[0])
                if fn is not None:
                    r = fn(*ins[1:])
                    vm.count += 1
                    if vm.trace is not None:
                        vm.trace.append((ins[0], list(ins[1:])[:3], r if not isinstance(r, str) else r[:24]))
                    if r is not None and g.get("__out__") is not None:
                        break
            return g.get(self.ret_slot)
        finally:
            g[9] = saved


class VM:
    """寄存器 Map g + 队列执行器。stub 由调用方注入（window/document 语义桩）。"""

    def __init__(self, stubs: dict | None = None, timeout_ms: int = 500, trace: list | None = None):
        self.g: dict = {}
        self.stubs = stubs or {}
        self.timeout_ms = timeout_ms
        self.count = 0
        self.trace = trace

    # ---- 内部工具 ----
    def _num(self, v):
        try:
            return float(v)
        except (TypeError, ValueError):
            return 0.0

    def _call(self, fn, *args):
        return fn(*args)

    def _res(self, x):
        """寄存器取值：int 且在表中 → 槽值；否则字面值（op7/13/17 的 args.map(g.get) 语义）"""
        return self.g[x] if isinstance(x, int) and x in self.g else x

    def _shift(self, q):
        """JS 数组 shift 语义：兼容 deque 与 list（dx 程序会用 op2 直写槽9 为数组）"""
        if isinstance(q, collections.deque):
            return q.popleft()
        return q.pop(0)

    def run(self, program: list, key: str) -> str:
        g = self.g
        self.count = 0
        g.clear()
        g[9] = collections.deque(program)      # 指令队列
        g[16] = key                            # XOR key 槽
        g[10] = self.stubs                     # window 注入（op24 绑定源）
        g[12] = g                              # 自引用
        # 处理器驻留寄存器表（与 JS g.set(0..35) 一致）——真实 dx 靠自安装浮点槽分发
        self._install(g)
        self._t0 = t0 = time.monotonic()
        while g[9]:
            if (time.monotonic() - t0) * 1000 > self.timeout_ms:
                return b64u(str(self.count))   # 超时 → btoa(指令计数)（turnstile 500ms 语义）
            ins = self._shift(g[9])
            op, args = ins[0], list(ins[1:])
            fn = g.get(op)
            if fn is None:
                continue                        # 未安装/空操作
            r = fn(*args)
            self.count += 1
            if self.trace is not None:
                self.trace.append((op, args[:3], None if not isinstance(r, str) else r[:24]))
            if r is not None and g.get("__out__") is not None:
                break
        return g.get("__out__") or b64u(str(self.count))

    # ---- 操作码安装（0-35；处理器驻留 g，真实 dx 经自安装浮点槽分发） ----
    def _install(self, g: dict):
        stubs = self.stubs
        g[3] = lambda v: g.setdefault("__out__", b64u(str(g.get(v, v))))   # resolve（槽号→槽值）
        g[4] = lambda v: g.setdefault("__err__", b64u(str(g.get(v, v))))   # reject

        def op0(subprog):
            # 子程序：切换槽9→跑完恢复（闭包语义简化版：直接嵌套执行）
            saved = g[9]
            g[9] = list(subprog)
            while g[9]:
                ins = self._shift(g[9])
                fn = g.get(ins[0])
                if fn:
                    fn(*ins[1:])
            g[9] = saved

        def op1(a, b):
            g[a] = xor_stream(str(g.get(a, "")), str(g.get(b, "")))

        def op2(slot, val):
            g[slot] = val

        def op5(a, b):
            x, y = g.get(a), g.get(b)
            if isinstance(x, str) or isinstance(y, str):
                g[a] = f"{x}{y}"
            else:
                g[a] = self._num(x) + self._num(y)

        def op6(dst, obj_slot, key_slot):
            obj = g.get(obj_slot) or {}
            g[dst] = obj.get(str(g.get(key_slot)))

        def op7(fn_slot, *args):
            fn = g.get(fn_slot)
            return fn(*[self._res(a) for a in args]) if callable(fn) else None

        def op8(dst, src):
            g[dst] = g.get(src)

        def op11(dst, regex_slot):
            srcs = [s.get("src", "") for s in stubs.get("document_scripts", [])]
            pat = re.compile(str(g.get(regex_slot)))
            for s in srcs:
                m = pat.search(s)
                if m and m.group(0):
                    g[dst] = m.group(0)
                    return

        def op13(dst, fn_slot, *args):
            try:
                fn = g.get(fn_slot)
                g[dst] = fn(*[self._res(a) for a in args]) if callable(fn) else None
            except Exception as e:
                g[dst] = str(e)

        def op14(dst, src):
            g[dst] = json.loads(g.get(src))

        def op15(dst, src):
            g[dst] = json.dumps(g.get(src), separators=(",", ":"))

        def op17(dst, fn_slot, *args):
            try:
                fn = g.get(fn_slot)
                g[dst] = fn(*[self._res(a) for a in args]) if callable(fn) else None
            except Exception as e:
                g[dst] = str(e)

        def op18(slot):
            g[slot] = base64.b64decode(str(g.get(slot)) + "=" * ((-len(str(g.get(slot)))) % 4)).decode()

        def op19(slot):
            g[slot] = b64u(str(g.get(slot)))

        def op20(a, b, fn, *rest):
            if g.get(a) == g.get(b):
                return g[fn](*rest)

        def op22(subprog, err_slot):
            saved = g[9]
            try:
                g[9] = list(subprog)
                while g[9]:
                    ins = self._shift(g[9])
                    fn = g.get(ins[0])
                    if fn:
                        fn(*ins[1:])
            except Exception as e:
                g[err_slot] = str(e)
            finally:
                g[9] = saved

        def op21(a, b, c, fn, *rest):
            if abs(self._num(g.get(a)) - self._num(g.get(b))) > self._num(g.get(c)):
                return g[fn](*rest)

        def op23(slot, fn, *rest):
            if g.get(slot) is not None:
                return g[fn](*rest)

        def op24(dst, obj_slot, key_slot):
            obj = g.get(obj_slot)
            k = str(g.get(key_slot))
            if isinstance(obj, dict) and k in obj:
                g[dst] = obj[k]

        def op27(a, b):
            x, y = g.get(a), g.get(b)
            if isinstance(x, list):
                try:
                    x.remove(y)
                except ValueError:
                    pass
            else:
                g[a] = self._num(x) - self._num(y)

        def op29(dst, a, b):
            g[dst] = self._num(g.get(a)) < self._num(g.get(b))

        def op30(slot_out, ret_slot, params, prog):
            # 函数定义：闭包对象（调用时绑定参数→嵌套执行 prog→取 ret_slot）
            g[slot_out] = VMFunction(self, ret_slot, params if isinstance(params, list) else [params],
                                     prog if isinstance(prog, list) else [])

        def op33(a, b):
            g[a] = self._num(g.get(a)) * self._num(g.get(b))

        def op34(dst, src):
            g[dst] = g.get(src)

        def op35(a, b):
            x, y = self._num(g.get(a)), self._num(g.get(b))
            g[a] = 0 if y == 0 else x / y

        g.update({0: op0, 1: op1, 2: op2, 5: op5, 6: op6, 7: op7, 8: op8, 11: op11,
                  13: op13, 14: op14, 15: op15, 17: op17, 18: op18, 19: op19, 20: op20,
                  21: op21, 22: op22, 23: op23, 24: op24, 27: op27, 29: op29, 30: op30,
                  33: op33, 34: op34, 35: op35})
        for nop in (25, 26, 28):
            g.setdefault(nop, lambda *a: None)


import re  # noqa: E402  (op11 需要)
