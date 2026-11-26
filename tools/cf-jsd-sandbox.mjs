// CF JSD main.js 动态分析沙箱：mock 浏览器环境，捕获脚本的读取行为与 POST 意图
// 用法: node cf-jsd-sandbox.mjs <main.js路径> <ray> <t_b64>
import fs from "node:fs";
import vm from "node:vm";

// main 包裹为异步（顶部 await 需要）
const main = async () => {
const [jsPath, ray, tb64] = process.argv.slice(2);
const js = fs.readFileSync(jsPath, "utf8");

const UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36";
const LOG = [];
const ATOB_LOG = [];
const log = (tag, data) => { LOG.push([tag, data]); console.log(`[${tag}] ${typeof data === "string" ? data.slice(0, 220) : JSON.stringify(data).slice(0, 220)}`); };

// —— 可捕获的传输层 mock ——
const POSTS = [];
// 真发模式：SHIPPING_FILE 存在时把每个 POST 写文件（Python 引擎读走真发）
const SHIPPING_FILE = process.env.CF_JSD_SHIP;
const ship = (post) => {
  if (!SHIPPING_FILE) return;
  try {
    const prev = fs.existsSync(SHIPPING_FILE) ? JSON.parse(fs.readFileSync(SHIPPING_FILE, "utf8")) : [];
    prev.push({ m: post.m, u: String(post.u), h: post.h || {}, b: post.b, at: Date.now() });
    fs.writeFileSync(SHIPPING_FILE, JSON.stringify(prev));
  } catch (e) { console.error("ship-err: " + String(e).slice(0, 80)); }
};
const mkXHR = () => class XHR {
  constructor() { this.readyState = 0; log("xhr-new", ""); }
  open(m, u) { this._m = m; this._u = u; log("xhr-open", `${m} ${u}`); }
  setRequestHeader(k, v) { (this._h = this._h || {})[k] = v; }
  send(b) {
    const post = { m: this._m, u: this._u, h: this._h, b: b ? String(b) : "" };
    POSTS.push(post);
    log("xhr-send", `${this._m} ${this._u} body=${String(b).slice(0, 160)}`);
    ship(post);
    // 模拟成功响应（onload 语义）
    this.readyState = 4;
    this.status = 200;
    this.responseText = "ok";
    if (typeof this._ol === "function") { try { this._ol(); } catch (e) { log("onload-err", String(e).slice(0, 120)); } }
  }
  addEventListener() {}
  set onload(f) { this._ol = f; } set onerror(f) {}
  get responseText() { return this._rt || "ok"; }
  set responseText(v) { this._rt = v; }
};
const mkFetch = () => async (u, o = {}) => {
  if ((o.method || "GET").toUpperCase() !== "GET") POSTS.push({ m: o.method, u: String(u), h: o.headers, b: o.body ? String(o.body) : "" });
  log("fetch", `${o.method || "GET"} ${String(u)} body=${o.body ? String(o.body).slice(0, 160) : ""}`);
  return { ok: true, status: 200, text: async () => "", json: async () => ({}) };
};
const mkBeacon = () => (u, d) => { POSTS.push({ m: "BEACON", u: String(u), h: {}, b: d ? String(d) : "" }); log("beacon", `${u} body=${d ? String(d).slice(0, 160) : ""}`); return true; };

const doc = {
  _els: [],
  createElement(tag) {
    const el = { tag, style: {}, attrs: {}, children: [], innerHTML: "", src: "", nonce: "", type: "", async: false,
      setAttribute(k, v) { this.attrs[k] = v; }, appendChild(c) { this.children.push(c); },
      addEventListener() {},
      get contentDocument() {
        // 模拟真实浏览器竞态：读取时抛错 → IL catch → e 触发 oneshot POST
        log("el-contentDocument-THROWS", tag);
        throw new TypeError("Blocked a frame with origin \"https://auth.openai.com\" from accessing a cross-origin frame.");
        return {
          head: { children: [], appendChild(c) { this.children.push(c); } },
          body: { children: [], appendChild(c) { this.children.push(c); } },
          documentElement: { children: [] },
          getElementsByTagName: (t) => {
            log("iframe-getByTag", t);
            if (t === "script") {
              // 信标注入器写入 main.js 的 script 元素
              return [{ tag: "script", src: `https://auth.openai.com/cdn-cgi/challenge-platform/h/b/scripts/jsd/f8df4d4a0cd6/main.js?ray=${ray}`, textContent: "" }];
            }
            return [];
          },
          querySelectorAll: () => [],
          readyState: "complete",
        };
      },
      get contentWindow() { log("el-contentWindow-THROWS", tag); throw new TypeError("cross-origin frame"); },
    };
    doc._els.push(el); log("doc-createElement", tag);
    return el;
  },
  getElementsByTagName(t) { log("doc-getByTag", t); return [doc._els.find(e => e.tag === t) || { appendChild(c) { log(`append-to-${t}`, c && c.tag); } }]; },
  head: null, body: null, documentElement: null, readyState: "complete",
  addEventListener(t, cb) { log("doc-addEventListener", t); if (typeof cb === "function") { try { cb({ type: t }); } catch (e) { log("doc-ev-err", String(e).slice(0, 120)); } } },
  cookie: "",
  currentScript: { src: `https://auth.openai.com/cdn-cgi/challenge-platform/h/b/scripts/jsd/f8df4d4a0cd6/main.js?ray=${ray}`,
                   nonce: "", async: false, type: "text/javascript",
                   getAttribute(k) { return k === "src" ? this.src : null; } },
  referrer: "",
  visibilityState: "visible",
  hidden: false,
  _onrsc: null,
  set onreadystatechange(f) {
    this._onrsc = f;
    log("doc-set-onreadystatechange", typeof f);
    if (typeof f === "function") {
      setImmediate(() => { try { f.call(this); } catch (e) { log("onrsc-err", String(e).slice(0, 120)); } });
    }
  },
  get onreadystatechange() { return this._onrsc; },
};

const ctx = {
  console: { log: () => {}, warn: () => {}, error: () => {}, info: () => {}, debug: () => {} },
  setTimeout: (f, ms) => { log("setTimeout", String(ms)); const id = setTimeout(() => { try { f(); } catch (e) { log("timer-err", String(e).slice(0, 140)); } }, 0); return id; },
  setInterval: (f, ms) => { log("setInterval", String(ms)); const id = setInterval(() => { try { f(); } catch (e) { log("interval-err", String(e).slice(0, 200)); clearInterval(id); } }, Math.min(ms || 1000, 100)); return id; },
  clearTimeout: (id) => { clearTimeout(id); }, clearInterval: (id) => { clearInterval(id); },
  Date, Math, JSON, String, Number, Array, Object, Boolean, RegExp, Error, TypeError, parseInt, parseFloat, isNaN, encodeURIComponent, decodeURIComponent, escape, unescape,
  atob: (s) => {
    const out = Buffer.from(s, "base64").toString("binary");
    ATOB_LOG.push(String(s));
    log("atob", `${String(s).slice(0, 40)} → ${out.replace(/[\x00-\x1f]/g, "·").slice(0, 160)}`);
    return out;
  },
  btoa: (s) => Buffer.from(s, "binary").toString("base64"),
  Uint8Array, Uint16Array, Uint32Array, Int8Array, Int16Array, Int32Array, Float32Array, Float64Array, ArrayBuffer, DataView, TextEncoder, TextDecoder,
  XMLHttpRequest: mkXHR(), fetch: mkFetch(), navigator: {
    userAgent: UA, language: "en-US", languages: ["en-US", "en"], platform: "Win32",
    plugins: { length: 5 }, mimeTypes: { length: 2 }, cookieEnabled: true, onLine: true,
    hardwareConcurrency: 8, deviceMemory: 8, maxTouchPoints: 0, webdriver: false,
    sendBeacon: mkBeacon(),
    connection: { downlink: 10, effectiveType: "4g", rtt: 50, saveData: false },
    getGamepads: () => [], javaEnabled: () => false,
  },
  screen: { width: 1920, height: 1080, availWidth: 1920, availHeight: 1040, colorDepth: 24, pixelDepth: 24, orientation: { type: "landscape-primary" } },
  devicePixelRatio: 1,
  location: { href: "https://auth.openai.com/cdn-cgi/challenge-platform/scripts/jsd/main.js", origin: "https://auth.openai.com", protocol: "https:", host: "auth.openai.com", hostname: "auth.openai.com", pathname: "/cdn-cgi/challenge-platform/scripts/jsd/main.js" },
  history: { length: 1 },
  performance: { now: () => Date.now() - 1000, timing: { navigationStart: Date.now() - 1000 }, getEntries: () => [], getEntriesByType: () => [] },
  addEventListener: (t) => log("win-addEventListener", t),
  removeEventListener: () => {},
  Image: class { set src(v) { log("image-src", String(v).slice(0, 140)); } },
  localStorage: { getItem: () => null, setItem: () => {}, removeItem: () => {} },
  sessionStorage: { getItem: () => null, setItem: () => {}, removeItem: () => {} },
  crypto: { getRandomValues: (a) => { for (let i = 0; i < a.length; i++) a[i] = (Math.random() * 256) | 0; return a; }, subtle: {}, randomUUID: () => "00000000-0000-4000-8000-000000000000" },
  TextDecoder, TextEncoder,
};
doc.head = { appendChild(c) { log("head-append", String(c && c.tag) + (c && c.src ? " src=" + String(c.src).slice(0, 100) : "")); } };
doc.body = doc.head;
// 万能对象：任何属性可读可调可构造，全量记录访问
const magic = new Proxy(function () {}, {
  get(t, k) {
    if (k === Symbol.toPrimitive) return () => "magic";
    if (k === "toString" || k === Symbol.toStringTag) return () => "magic";
    if (k === "then") return undefined;
    log("magic-get", String(k));
    return magic;
  },
  apply() { log("magic-apply", ""); return magic; },
  construct() { log("magic-construct", ""); return magic; },
  has() { return true; },
});

const parentWin = new Proxy({ location: ctx.location }, {
  get(t, k) {
    if (k in t) { log("parent-read", `${String(k)} → ${typeof t[k] === "object" ? "[obj]" : String(t[k]).slice(0, 60)}`); return t[k]; }
    log("parent-get-missing", String(k));
    return undefined;
  },
  set(t, k, v) { t[k] = v; log("parent-set", String(k)); return true; },
  has() { return true; },
});
const win = new Proxy({
  _cf_chl_opt: undefined,
  __CF$cv$params: { r: ray, t: tb64, interval: 1000 },
  _cf_chl_state: { cv: { r: ray, t: tb64 }, interval: 1000 },
  cf_chl_prog: 0,
  document: doc,
  navigator: ctx.navigator, screen: ctx.screen, location: ctx.location, performance: ctx.performance,
  XMLHttpRequest: ctx.XMLHttpRequest, fetch: ctx.fetch, Image: ctx.Image,
  localStorage: ctx.localStorage, sessionStorage: ctx.sessionStorage, crypto: ctx.crypto,
  devicePixelRatio: 1, history: ctx.history, atob: ctx.atob, btoa: ctx.btoa,
  setTimeout: ctx.setTimeout, setInterval: ctx.setInterval, clearTimeout: ctx.clearTimeout,
  addEventListener: ctx.addEventListener, Date: ctx.Date, Math: ctx.Math,
  parent: parentWin,
  frameElement: { src: "about:blank", style: {}, width: 1, height: 1 },
  name: "",
  origin: "https://auth.openai.com",
  closed: false,
  frames: [],
  length: 0,
  top: null,
}, {
  get(t, k) {
    if (k in t) { log("win-read", `${String(k)} → ${typeof t[k] === "object" ? "[obj]" : String(t[k]).slice(0, 60)}`); return t[k]; }
    if (k in ctx) { log("win-read-ctx", String(k)); return ctx[k]; }
    log("win-get-missing", String(k));
    return undefined;
  },
  set(t, k, v) { t[k] = v; const sv = (() => { try { return String(v).slice(0, 120); } catch { return `[${typeof v}]`; } })(); log("win-set", `${String(k)} = ${sv}`); return true; },
  has(t, k) { if (k in t) return true; if (k in ctx) return true; return false; },
});
win.top = win;
ctx.window = win;
ctx.self = win;
ctx.globalThis = win;
ctx.parent = win.parent;
// 关键：VM 内顶层 this = global proxy（即 vm context 化后的 ctx），属性查找走 ctx
// 把信标参数直接挂 ctx，VM 的 Wr[2]=this 才能读到
ctx.__CF$cv$params = { r: ray, t: tb64, interval: 1000 };
ctx._cf_chl_state = { cv: { r: ray, t: tb64 }, interval: 1000, _61819e8f91c95d4afcbef7fb: "b" };
ctx._cf_chl_opt = { _61819e8f91c95d4afcbef7fb: "b" };
ctx.__probe = (s) => { console.log("[PROBE] " + String(s).slice(0, 200)); };
ctx.document = doc;
ctx.navigator = ctx.navigator;
ctx.XMLHttpRequest = ctx.XMLHttpRequest;
ctx.location = ctx.location;
ctx.setTimeout = ctx.setTimeout;
ctx.setInterval = ctx.setInterval;
ctx.clearTimeout = ctx.clearTimeout;
ctx.clearInterval = ctx.clearInterval;
ctx.Image = ctx.Image;
ctx.fetch = ctx.fetch;
// 全局吞异常拦截：VM 内 catch 分支把错误送出来
ctx.__swallow = (e) => { console.log("[VM-ERR] " + String(e).slice(0, 300)); };
ctx.document = doc;
ctx.navigator = ctx.navigator;
ctx.XMLHttpRequest = ctx.XMLHttpRequest;
ctx.location = ctx.location;
ctx.setTimeout = ctx.setTimeout; ctx.setInterval = ctx.setInterval;
ctx.clearTimeout = ctx.clearTimeout; ctx.clearInterval = ctx.clearInterval;

try {
  vm.createContext(ctx);
  // 插桩：给字符串查表器注入访问日志（VM 执行路径追踪）
  const hook = 'return function(T){console.log("STR:"+String(T));var o=h[T];';
  const patched = js.replace(/return function\(T\)\{var o=h\[T\];/, hook);
  if (patched === js) console.log("!!! 字符串查表器模式未命中，跑原版");
  const script = new vm.Script(patched, { filename: "cf-jsd-main.js" });
  // VM 内 console.log 落到文件
  const STR_TRACE = [];
  ctx.console = { ...ctx.console, log: (...a) => { STR_TRACE.push(a.join(" ")); } };
  script.runInContext(ctx, { timeout: 8000 });
  console.log(`\n=== 脚本执行完毕，字符串访问 ${STR_TRACE.length} 次:`);
  for (const s of STR_TRACE.slice(0, 80)) console.log("  " + s.slice(0, 80));
  fs.writeFileSync(jsPath + ".strtrace.json", JSON.stringify(STR_TRACE, null, 1));
} catch (e) {
  console.log(`\n=== 脚本异常: ${String(e).slice(0, 150)}`);
  if (e && e.stack) {
    const lines = String(e.stack).split("\n");
    for (const ln of lines.slice(0, 8)) console.log("  " + ln.slice(0, 170));
  }
}
// 等异步定时器窗口跑完再收尾
await new Promise((r) => setTimeout(r, 2500));
console.log(`[X5-STEP] last=${ctx.__st}`);
console.log(`\n=== 捕获 POST 意图 ${POSTS.length} 个:`);
for (const p of POSTS) {
  console.log(`  ${p.m} ${String(p.u).slice(0, 160)}`);
  console.log(`     body[:400]: ${String(p.b).slice(0, 400)}`);
}
fs.writeFileSync(jsPath + ".posts.json", JSON.stringify(POSTS, null, 1));
fs.writeFileSync(jsPath + ".atob.json", JSON.stringify(ATOB_LOG, null, 1));
console.log(`atob 输入已存: ${jsPath}.atob.json (${ATOB_LOG.length} 条)`);
process.exit(0);

};
main().catch((e) => console.error(String(e)));
