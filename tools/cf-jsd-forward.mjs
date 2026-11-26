// Node 转发层：stdin 收 JSON 请求 → Node fetch 发（同指纹）→ stdout 回 JSON 响应
// 用法: node cf-jsd-forward.mjs < 尾随式命令循环
// 协议: 每行一个 JSON {"id":1,"url":"...","method":"GET","headers":{},"body":"..."}
//        回 {"id":1,"status":200,"headers":{...},"body":"...","cookies":{...}}
// jar 由本进程持有（cf_clearance 等自动带上+自动收 set-cookie）
import readline from "node:readline";

const jar = {};
const cookieHeader = () => Object.entries(jar).map(([k, v]) => `${k}=${v}`).join("; ");
const rl = readline.createInterface({ input: process.stdin, terminal: false });

rl.on("line", async (line) => {
  let req;
  try { req = JSON.parse(line); } catch { send({ id: null, error: "bad-json" }); return; }
  if (req._setjar) { jar[req.name] = req.value; send({ id: req.id, ok: true }); return; }
  try {
    const h = { ...(req.headers || {}) };
    // 合并 jar（请求头已有 Cookie 的合并）
    if (jar && Object.keys(jar).length) {
      const given = h["Cookie"] || h["cookie"] || "";
      h["Cookie"] = (given ? given + "; " : "") + cookieHeader();
    }
    const opts = { method: req.method || "GET", headers: h, redirect: req.redirect || "manual" };
    if (req.body) opts.body = req.body;
    const resp = await fetch(req.url, opts);
    // 收 set-cookie
    const sc = resp.headers.getSetCookie ? resp.headers.getSetCookie() : [];
    for (const c of sc) {
      const nv = c.split(";")[0];
      if (nv.includes("=")) {
        const [nm, ...rest] = nv.split("=");
        if (nm === "__cf_bm" || rest.join("=").length < 2000) jar[nm] = rest.join("=");
      }
    }
    const headers = {};
    for (const [k, v] of resp.headers) if (k !== "set-cookie") headers[k] = v;
    const body = await resp.text();
    send({ id: req.id, status: resp.status, headers, body: body.slice(0, 500000), jar: { ...jar } });
  } catch (e) {
    send({ id: req.id, error: String(e).slice(0, 300) });
  }
});
function send(obj) { process.stdout.write(JSON.stringify(obj) + "\n"); }
