// SPDX-License-Identifier: GPL-2.0
// bun bun.mjs <json|gzip> [samples=7] [warmups=3] [label=process.arch]
// Fixed work per sample, identical across architectures. Excludes startup.
const [name, sampleArg = '7', warmupArg = '3', label = process.arch] = process.argv.slice(2);
const samples = Number(sampleArg), warmups = Number(warmupArg);
if (!Number.isInteger(samples) || samples < 1 || !Number.isInteger(warmups) || warmups < 0)
  throw new Error('Expected positive samples and nonnegative warmups');

let run;
if (name === 'json') {
  const value = Array.from({length: 10_000}, (_, i) =>
    ({id: i, label: `item-${i}`, enabled: (i & 1) === 0, values: [i, i + 1, i + 2]}));
  const source = JSON.stringify(value);
  run = () => {
    let sum = 0;
    for (let i = 0; i < 20; i++) {
      const parsed = JSON.parse(source);
      const serialized = JSON.stringify(parsed);
      if (serialized !== source) throw new Error('JSON round trip mismatch');
      sum += serialized.length + parsed[9999].id;
    }
    return sum;
  };
} else if (name === 'gzip') {
  const data = new Uint8Array(1024 * 1024);
  let x = 0x12345678;
  for (let i = 0; i < data.length; i++) {
    x = Math.imul(x, 1664525) + 1013904223 | 0;
    data[i] = i % 97 < 64 ? 97 + i % 23 : x >>> 24;
  }
  const digest = new Bun.CryptoHasher('sha256').update(data).digest('hex');
  run = () => {
    let zipped;
    for (let i = 0; i < 8; i++) zipped = Bun.gzipSync(data, {level: 6});
    const restored = Bun.gunzipSync(zipped);
    const hash = new Bun.CryptoHasher('sha256').update(restored).digest('hex');
    if (hash !== digest) throw new Error('gzip round trip mismatch');
    return hash;
  };
} else {
  throw new Error('Usage: bun bun.mjs <json|gzip> [samples=7] [warmups=3] [label]');
}

console.log('BEGIN ' + JSON.stringify({name, label, arch: process.arch, version: Bun.version, samples, warmups}));
let expected;
for (let i = 0; i < warmups; i++) expected = run();
for (let sample = 0; sample < samples; sample++) {
  const start = performance.now();
  const checksum = run();
  const ms = performance.now() - start;
  if (expected !== undefined && checksum !== expected) throw new Error('Unstable checksum');
  expected = checksum;
  console.log('RESULT ' + JSON.stringify({name, label, sample, ms, checksum}));
}
