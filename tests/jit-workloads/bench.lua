-- JIT stress for LuaJIT: traces, side exits, many generated chunks, FFI-free.
local bit = bit or require("bit")
local h = 2166136261
local function mix(v) h = bit.tobit(bit.bxor(h, bit.tobit(v)) * 16777619) end
local scale = tonumber(arg and arg[1]) or 1

-- 1. hot loops with branchy bodies (side traces)
local acc = 0
for i = 1, 5e6 * scale do
  if i % 3 == 0 then acc = acc + i elseif i % 5 == 0 then acc = acc - i else acc = acc + 1 end
end
mix(acc % 2^31)

-- 2. type-unstable loop (trace aborts/re-records)
local t = {}
for i = 1, 200000 do t[i] = (i % 7 == 0) and tostring(i) or i end
local s = 0
for r = 1, 5 * scale do for i = 1, #t do local v = t[i]; s = s + (type(v) == "string" and #v or v % 13) end end
mix(s % 2^31)

-- 3. many generated functions
for i = 1, 2000 * scale do
  local f = load(("return function(x) local y = x for j = 1, %d do y = (y * %d + j) %% 1000003 end return y end")
    :format(i % 11 + 5, i % 7 + 3))()
  local y = 0
  for j = 1, 300 do y = f(y + j) end
  mix(y)
end

-- 4. n-body
local function nbody(n)
  local b = {}
  for i = 1, 5 do b[i] = {x = i, y = i * 2, z = i * 3, vx = 0, vy = 0, vz = 0, m = i} end
  for _ = 1, n do
    for i = 1, 5 do local bi = b[i]
      for j = i + 1, 5 do local bj = b[j]
        local dx, dy, dz = bi.x - bj.x, bi.y - bj.y, bi.z - bj.z
        local d2 = dx * dx + dy * dy + dz * dz + 0.01
        local mag = 0.001 / (d2 * math.sqrt(d2))
        bi.vx = bi.vx - dx * bj.m * mag; bj.vx = bj.vx + dx * bi.m * mag
        bi.vy = bi.vy - dy * bj.m * mag; bj.vy = bj.vy + dy * bi.m * mag
        bi.vz = bi.vz - dz * bj.m * mag; bj.vz = bj.vz + dz * bi.m * mag
      end
    end
    for i = 1, 5 do local bi = b[i]; bi.x = bi.x + 0.001 * bi.vx; bi.y = bi.y + 0.001 * bi.vy; bi.z = bi.z + 0.001 * bi.vz end
  end
  return b[1].x + b[2].y + b[3].z
end
mix(math.floor(nbody(200000 * scale) * 1e6))

-- 5. string building / gsub
local parts = {}
for i = 1, 50000 do parts[#parts + 1] = ("k%d=%d"):format(i, i * 7919 % 1000) end
local str = table.concat(parts, ";")
local total = 0
for v in str:gmatch("=(%d+)") do total = total + tonumber(v) end
mix(total)

print(("lua checksum %08x"):format(h % 2^32))
