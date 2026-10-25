// JIT stress for V8: hot loops, deopts, megamorphic calls, generated code,
// regexps (compiled to native code), wasm, typed arrays, GC churn.
'use strict';
let h = 0x811c9dc5 >>> 0;
const mix = v => { h = Math.imul(h ^ (v >>> 0), 16777619) >>> 0; };
const scale = Number(process.argv[2] || 1);

// 1. hot numeric loop with a type change halfway (forces deopt + reopt)
function poly(a, b) { return a * 31 + b; }
let acc = 0;
for (let i = 0; i < 2e6 * scale; i++) acc = (poly(acc | 0, i) | 0);
mix(acc);
let accs = '';
for (let i = 0; i < 2e4; i++) accs = String(poly(accs.length, i)).slice(-6);
mix(Number(accs));

// 2. megamorphic property access over many shapes
const objs = [];
for (let i = 0; i < 64; i++) { const o = {}; o['k' + i] = i; o.v = i * 3; objs.push(o); }
let s = 0;
for (let r = 0; r < 20000 * scale; r++) for (const o of objs) s = (s + o.v) | 0;
mix(s);

// 3. lots of generated functions (new code each time; old code is collected)
for (let i = 0; i < 3000 * scale; i++) {
  const f = new Function('x', `let y = x; for (let j = 0; j < ${i % 13 + 5}; j++) y = (y * ${i % 7 + 3} + j) | 0; return y;`);
  let y = 0;
  for (let j = 0; j < 200; j++) y = f(y + j);
  mix(y);
}

// 4. regexps
const text = Array.from({ length: 2000 }, (_, i) => `item${i}=${(i * 7919) % 1000};`).join('');
for (let i = 0; i < 20 * scale; i++) {
  const re = new RegExp(`item(\\d*${i % 10})=(\\d+);`, 'g');
  let m, c = 0;
  while ((m = re.exec(text))) c += Number(m[2]);
  mix(c);
}

// 5. wasm: (func (param i32) (result i32)) computing a loop sum
const wasm = new Uint8Array([0,97,115,109,1,0,0,0,1,6,1,96,1,127,1,127,3,2,1,0,7,5,1,1,102,0,0,10,
  31,1,29,1,1,127,3,64,32,1,32,0,106,65,231,7,108,33,1,32,0,65,1,107,34,0,13,0,11,32,1,11]);
// (--jitless has no WebAssembly: same function in JS)
const f = typeof WebAssembly === 'object'
  ? new WebAssembly.Instance(new WebAssembly.Module(wasm)).exports.f
  : n => { let a = 0; do { a = Math.imul(a + n, 999); } while (--n); return a; };
for (let i = 0; i < 200 * scale; i++) mix(f(1000 + i));

// 6. typed arrays + sort + GC churn
const ta = new Float64Array(200000);
for (let i = 0; i < ta.length; i++) ta[i] = Math.sin(i) * 1e6;
ta.sort();
mix(Math.round(ta[1234] * 1000) | 0);
let keep = [];
for (let i = 0; i < 300000 * scale; i++) { keep.push({ i, s: 'x' + (i % 1000) }); if (keep.length > 5000) keep = []; }
mix(keep.length);

// 7. JSON round trip
const big = { a: Array.from({ length: 20000 }, (_, i) => ({ i, t: i % 3 ? 'a' : 'b', f: i / 7 })) };
mix(JSON.stringify(JSON.parse(JSON.stringify(big))).length);

console.log('js checksum', h.toString(16));
