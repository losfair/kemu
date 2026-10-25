# JIT stress for PyPy (and a CPython oracle): hot loops, polymorphism,
# generated code via exec, dicts, strings, generators, bigints.
import sys
h = 0x811c9dc5
def mix(v):
    global h
    h = ((h ^ (v & 0xffffffff)) * 16777619) & 0xffffffff
scale = int(sys.argv[1]) if len(sys.argv) > 1 else 1

acc = 0
for i in range(3_000_000 * scale):
    acc = (acc * 31 + (i ^ (acc >> 7))) & 0xffffffffffff
mix(acc)

class A:
    def f(self, x): return x + 1
class B:
    def f(self, x): return x * 2 % 1000003
class C:
    def f(self, x): return x - 3
class D(A):
    def f(self, x): return super().f(x) ^ 5
objs = [A(), B(), C(), D()] * 50
s = 0
for r in range(5000 * scale):
    for o in objs:
        s = o.f(s) % 1000003
mix(s)

for i in range(500 * scale):
    ns = {}
    exec(f"def g(x):\n    y = x\n    for j in range({i % 13 + 5}):\n        y = (y * {i % 7 + 3} + j) % 1000003\n    return y\n", ns)
    y = 0
    for j in range(300):
        y = ns["g"](y + j)
    mix(y)

d = {}
for i in range(300000 * scale):
    k = "k%d" % (i % 5000)
    d[k] = d.get(k, 0) + i
mix(sum(d.values()))

def gen(n):
    a, b = 0, 1
    for _ in range(n):
        yield a
        a, b = b, a + b
mix(sum(gen(2000)) % (1 << 61))
mix(len(",".join(str(i * 7919 % 1000) for i in range(200000))))
print("py checksum %08x" % h)
