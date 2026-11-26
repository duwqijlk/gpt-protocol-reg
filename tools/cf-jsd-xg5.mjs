// v52：干净版 v51（无 # 注释）——XF-tail 终极探针
import fs from "node:fs";
import vm from "node:vm";

const orig = fs.readFileSync(String.raw`C:\Users\Administrator\Desktop\GPT新版本协议研究\build\params\cf-jsd-main.js`, "utf8");
let cur = orig;
const plan = [
  ["P1", "Xe=Wr[1237119090^_0xb5eaa4]=this||self,Wv=Wr[1237119090^_0xb5eaa4][", '(0,__probe)("P1"),Xe=Wr[1237119090^_0xb5eaa4]=this||self,Wv=Wr[1237119090^_0xb5eaa4]['],
  ["P5", "(0,Wr[1237119088^_0xb5eaa4])(XC);", '(0,__probe)("P5"),(0,Wr[1237119088^_0xb5eaa4])(XC);'],
  ["XF", "function XF(Xr){var Xv;var Xx;Xv=`e`,", 'function XF(Xr){__probe("XF-enter");var Xv;var Xx;Xv=`e`,'],
  ["ILerr", "catch(GL){var HL;return HL={},HL[`r`]={},HL[`e`]=GL,HL}", 'catch(GL){__probe("IL-ERR");var HL;return HL={},HL[`r`]={},HL[`e`]=GL,HL}'],
  ["XFtail", "Xx[Xv]&&hM(416462914^_0xb5eaa4,", '__probe("XF-tail"),Xx[Xv]&&hM(416462914^_0xb5eaa4,'],
  ["hMpost", "case 416462914:{var OL;var PL;", 'case 416462914:{__probe("hM-post");var OL;var PL;'],
  ["hMser", "case 1465676357:{var gM;", 'case 1465676357:{__probe("hM-ser");var gM;'],
];
let placed = [];
for (const [tag, anchor, probe] of plan) {
  const next = cur.replace(anchor, probe);
  if (next === cur) { console.log(tag + ": MISS"); continue; }
  try { new vm.Script(next); cur = next; placed.push(tag); }
  catch (e) { console.log(tag + ": BAD " + String(e).slice(0, 50)); }
}
const xn = cur.replace("function XN(Xx){return Math[d9||(d9=ab(`wWzdadxg`))]()<Xx}", "function XN(Xx){return true}");
if (xn !== cur) { cur = xn; placed.push("XN"); }
console.log("placed: " + placed.join(","));
fs.writeFileSync(String.raw`C:\Users\Administrator\Desktop\GPT新版本协议研究\build\params\cf-jsd-main-instr.js`, cur);
