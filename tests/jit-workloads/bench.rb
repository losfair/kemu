# JIT stress for Ruby (YJIT when available).
$h = 0x811c9dc5
def mix(v) = $h = (($h ^ (v & 0xffffffff)) * 16777619) & 0xffffffff
scale = (ARGV[0] || 1).to_i
acc = 0
(3_000_000 * scale).times { |i| acc = (acc * 31 + (i ^ (acc >> 7))) & 0xffffffffffff }
mix(acc)
class A; def f(x) = x + 1; end
class B; def f(x) = x * 2 % 1000003; end
class C; def f(x) = x - 3; end
objs = [A.new, B.new, C.new] * 50
s = 0
(5000 * scale).times { objs.each { |o| s = o.f(s) % 1000003 } }
mix(s)
(500 * scale).times do |i|
  m = Module.new
  m.module_eval("def self.g(x); y = x; #{i % 13 + 5}.times { |j| y = (y * #{i % 7 + 3} + j) % 1000003 }; y; end")
  y = 0
  300.times { |j| y = m.g(y + j) }
  mix(y)
end
d = Hash.new(0)
(300000 * scale).times { |i| d["k#{i % 5000}"] += i }
mix(d.values.sum)
mix((0...200000).map { |i| (i * 7919 % 1000).to_s }.join(",").size)
puts format("rb checksum %08x", $h)
