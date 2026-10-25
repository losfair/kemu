#!/bin/bash
# Run the JIT stress workloads inside an arm64 userland, each with the
# guest runtime's JIT on and off, and compare checksums.
#   run.sh [scale] [rounds]
# Every runtime's JIT-off output is the oracle for its JIT-on output.
# expected.txt holds checksums from native x86_64 runs where available.
cd "$(dirname "$0")" || exit 1
scale=${1:-1}
rounds=${2:-1}
TIMEFORMAT='%R s'
fails=0
tmp=$(mktemp -d)
expect() { [ "$scale" = 1 ] && grep "^$1 " expected.txt | cut -d' ' -f2; }

check() {	# name, then command for JIT on / JIT off as two strings
	local name=$1 on=$2 off=$3 a b want t
	command -v "${on%% *}" >/dev/null || { echo "SKIP $name"; return; }
	for r in $(seq "$rounds"); do
		t=$( { time bash -c "$on" > "$tmp/on" 2>&1; } 2>&1 )
		a=$(tail -1 "$tmp/on")
		if [ "$r" = 1 ]; then
			b=$(bash -c "$off" 2>&1 | tail -1)
		fi
		want=$(expect "$name")
		if [ "$a" != "$b" ] || { [ -n "$want" ] && [ "${a##* }" != "$want" ]; }; then
			echo "FAIL $name round $r: jit='$a' nojit='$b' native='${want:-?}'"
			tail -5 "$tmp/on" | sed 's/^/    /'
			fails=$((fails + 1))
		else
			echo "ok   $name round $r: $a ($t)"
		fi
	done
}

java_classes=$tmp/classes
mkdir -p "$java_classes"
if command -v javac >/dev/null; then
	if t=$( { time javac -d "$java_classes" Bench.java > "$tmp/javac" 2>&1; } 2>&1 ); then
		echo "ok   javac ($t)"
	else
		echo "FAIL javac (exit $?)"
		tail -20 "$tmp/javac" | sed 's/^/    /'
		fails=$((fails + 1))
	fi
fi

check node   "node bench.js $scale"                          "node --jitless bench.js $scale"
check java   "java -cp $java_classes Bench $scale"           "java -Xint -cp $java_classes Bench $scale"
check luajit "luajit bench.lua $scale"                       "luajit -joff bench.lua $scale"
check pypy3  "pypy3 bench.py $scale"                         "python3 bench.py $scale"
check ruby   "ruby --yjit bench.rb $scale"                   "ruby bench.rb $scale"
check python3 "python3 bench.py $scale"                      "python3 bench.py $scale"
rm -rf "$tmp"
echo "jit-workloads: $fails failures"
exit $((fails > 0))
