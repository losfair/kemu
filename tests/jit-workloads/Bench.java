// JIT stress for HotSpot: C1/C2 tiers, deopts, megamorphic calls, lambdas,
// generated classes (lambda forms), threads, ConcurrentHashMap, streams.
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import java.util.function.*;
import java.util.stream.*;

public class Bench {
    static int h = 0x811c9dc5;
    static void mix(long v) { h = (h ^ (int) v ^ (int) (v >>> 32)) * 16777619; }

    interface Shape { double area(); }
    record Sq(double s) implements Shape { public double area() { return s * s; } }
    record Ci(double r) implements Shape { public double area() { return 3 * r * r; } }
    record Tr(double b, double t) implements Shape { public double area() { return b * t / 2; } }
    record Re(double w, double t) implements Shape { public double area() { return w * t; } }

    public static void main(String[] a) throws Exception {
        int scale = a.length > 0 ? Integer.parseInt(a[0]) : 1;
        // 1. hot loop, then a type change (deopt)
        long acc = 0;
        for (int i = 0; i < 20_000_000 * scale; i++) acc = acc * 31 + (i ^ (acc >>> 7));
        mix(acc);
        // 2. megamorphic interface calls
        Shape[] sh = new Shape[1000];
        for (int i = 0; i < sh.length; i++)
            sh[i] = switch (i % 4) { case 0 -> new Sq(i); case 1 -> new Ci(i); case 2 -> new Tr(i, 2); default -> new Re(i, 3); };
        double ar = 0;
        for (int r = 0; r < 2000 * scale; r++) for (Shape s : sh) ar += s.area();
        mix((long) ar);
        // 3. lambdas and streams (generated classes)
        List<Function<Long, Long>> fs = new ArrayList<>();
        for (int i = 0; i < 50; i++) { final int k = i; fs.add(x -> x * (k + 3) + k); }
        long y = 1;
        for (int r = 0; r < 20000 * scale; r++) y = fs.get(r % fs.size()).apply(y) % 1_000_003;
        mix(y);
        mix(IntStream.range(0, 2_000_000).filter(i -> i % 3 == 0).mapToLong(i -> (long) i * i % 1000).sum());
        // 4. threads + ConcurrentHashMap + atomics
        ConcurrentHashMap<Integer, Long> m = new ConcurrentHashMap<>();
        AtomicLong al = new AtomicLong();
        ExecutorService ex = Executors.newFixedThreadPool(4);
        List<Future<?>> fu = new ArrayList<>();
        for (int t = 0; t < 4; t++) {
            final int tt = t;
            fu.add(ex.submit(() -> {
                for (int i = 0; i < 300_000 * scale; i++) { m.merge(i % 5000, (long) i, Long::sum); al.addAndGet(i ^ tt); }
            }));
        }
        for (Future<?> f : fu) f.get();
        ex.shutdown();
        long ms = 0;
        for (long v : m.values()) ms += v;
        mix(ms); mix(al.get());
        // 5. sorting + strings
        Random rnd = new Random(42);
        int[] arr = new int[2_000_000];
        for (int i = 0; i < arr.length; i++) arr[i] = rnd.nextInt();
        Arrays.sort(arr);
        mix(arr[12345]);
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 200000; i++) sb.append(i % 97).append(',');
        mix(sb.toString().hashCode());
        mix(Arrays.stream(sb.toString().split(",")).mapToInt(Integer::parseInt).sum());
        System.out.printf("java checksum %08x%n", h);
    }
}
