# SPDX-License-Identifier: GPL-2.0
"""Tiny evaluator for the decode-time subset of Arm ASL.

Only what is needed to decide whether a concrete instruction word is
UNDEFINED / NOP / allocated according to an encoding's ASL decode block:
`let`/`var` bindings, `if/elsif/else`, `case ... of when`, `EndOfDecode(...)`,
bit-literal comparisons (with 'x' wildcards), `::` concatenation, slices,
`IN {..}`, UInt/SInt and IsFeatureImplemented. Anything else evaluates to
UNKNOWN, which propagates.
"""
import re


class _Unknown:
    def __repr__(self):
        return "UNKNOWN"


UNKNOWN = _Unknown()


class Bits:
    __slots__ = ("v", "w")

    def __init__(self, v, w):
        self.v = v & ((1 << w) - 1) if w > 0 else 0
        self.w = w

    def __repr__(self):
        return "'" + format(self.v, "0%db" % self.w) + "'" if self.w else "''"


class Pat:
    """Bit pattern literal with x wildcards."""
    __slots__ = ("m", "v", "w")

    def __init__(self, s):
        self.w = len(s)
        self.m = int("".join("0" if c == "x" else "1" for c in s), 2) if s else 0
        self.v = int("".join("1" if c == "1" else "0" for c in s), 2) if s else 0

    def match(self, b):
        return (b.v & self.m) == self.v


class EndDecode(Exception):
    def __init__(self, kind):
        self.kind = kind


class Unk(Exception):
    pass


TOK = re.compile(r"\s*(?:(//[^\n]*)|('[01x ]*')|(\"[^\"]*\")|(0x[0-9a-fA-F_]+|\d+)|([A-Za-z_][A-Za-z0-9_.]*)|(::|==|!=|<=|>=|&&|\|\||=>|<<|>>|\+:|[()\[\]{},;:=!<>+\-*/^.]))")

KEYWORDS = {"if", "then", "elsif", "else", "end", "case", "of", "when", "otherwise",
            "let", "var", "constant", "for", "to", "downto", "do", "while", "return",
            "where", "IN", "DIV", "MOD", "AND", "OR", "EOR", "NOT", "repeat", "until",
            "begin", "assert", "array", "of"}


def tokenize(s):
    out = []
    pos = 0
    while pos < len(s):
        m = TOK.match(s, pos)
        if not m:
            if s[pos:].strip() == "":
                break
            raise SyntaxError("bad char %r at %d" % (s[pos], pos))
        pos = m.end()
        if m.group(1):
            continue
        if m.group(2) is not None:
            out.append(("bits", m.group(2)[1:-1].replace(" ", "")))
        elif m.group(3) is not None:
            out.append(("str", m.group(3)))
        elif m.group(4) is not None:
            out.append(("num", int(m.group(4).replace("_", ""), 0)))
        elif m.group(5) is not None:
            out.append(("id", m.group(5)))
        else:
            out.append(("op", m.group(6)))
    out.append(("eof", None))
    return out


class Interp:
    def __init__(self, toks, env, features):
        self.t = toks
        self.i = 0
        self.env = env  # name -> value
        self.features = features
        self.saw_unknown_end = False

    # ---- token helpers ----
    def peek(self, k=0):
        return self.t[min(self.i + k, len(self.t) - 1)]

    def isop(self, s, k=0):
        tk = self.peek(k)
        return tk[0] == "op" and tk[1] == s

    def isid(self, s, k=0):
        tk = self.peek(k)
        return tk[0] == "id" and tk[1] == s

    def take(self):
        tk = self.t[self.i]
        self.i += 1
        return tk

    def expect_op(self, s):
        tk = self.take()
        if tk != ("op", s):
            raise SyntaxError("expected %s got %r" % (s, tk))

    def expect_id(self, s):
        tk = self.take()
        if tk != ("id", s):
            raise SyntaxError("expected %s got %r" % (s, tk))

    # ---- statements ----
    def run(self):
        self.stmts(execute=True)

    def stmts(self, execute):
        while True:
            tk = self.peek()
            if tk[0] == "eof":
                return
            if tk[0] == "id" and tk[1] in ("end", "elsif", "else", "when", "otherwise"):
                return
            self.stmt(execute)

    def skip_to_semi(self):
        depth = 0
        while True:
            tk = self.take()
            if tk[0] == "eof":
                return
            if tk[0] == "op" and tk[1] in "([{":
                depth += 1
            elif tk[0] == "op" and tk[1] in ")]}":
                depth -= 1
            elif tk == ("op", ";") and depth <= 0:
                return

    def stmt(self, execute):
        tk = self.peek()
        if tk == ("id", "if"):
            self.take()
            branches = []
            cond = self.expr()
            self.expect_id("then")
            taken = False
            unknown = False
            c = self.truth(cond) if execute else False
            if c is UNKNOWN:
                unknown = True
            self.branch_body(execute and c is True, execute and c is UNKNOWN)
            if c is True:
                taken = True
            while self.isid("elsif"):
                self.take()
                cond = self.expr()
                self.expect_id("then")
                c2 = self.truth(cond) if (execute and not taken) else False
                run = execute and not taken and not unknown and c2 is True
                unk = execute and not taken and (unknown or c2 is UNKNOWN)
                if c2 is UNKNOWN:
                    unknown = True
                self.branch_body(run, unk)
                if run:
                    taken = True
            if self.isid("else"):
                self.take()
                run = execute and not taken and not unknown
                self.branch_body(run, execute and not taken and unknown)
            self.expect_id("end")
            self.expect_op(";")
            return
        if tk == ("id", "case"):
            self.take()
            subj = self.expr()
            self.expect_id("of")
            taken = False
            unknown = subj is UNKNOWN
            while self.isid("when"):
                self.take()
                pats = [self.expr()]
                while self.isop(","):
                    self.take()
                    pats.append(self.expr())
                guard = None
                if self.isid("where"):
                    self.take()
                    guard = self.expr()
                self.expect_op("=>")
                m = False
                if execute and not taken and not unknown:
                    m = UNKNOWN
                    res = False
                    for p in pats:
                        r = self.eq(subj, p)
                        if r is True:
                            res = True
                            break
                        if r is UNKNOWN:
                            res = UNKNOWN
                    m = res
                    if m is True and guard is not None:
                        g = self.truth(guard)
                        m = g
                run = execute and not taken and not unknown and m is True
                unk = execute and not taken and (unknown or m is UNKNOWN)
                if m is UNKNOWN:
                    unknown = True
                self.branch_body(run, unk)
                if run:
                    taken = True
            if self.isid("otherwise"):
                self.take()
                self.expect_op("=>")
                self.branch_body(execute and not taken and not unknown, execute and not taken and unknown)
            self.expect_id("end")
            self.expect_op(";")
            return
        if tk[0] == "id" and tk[1] in ("let", "var", "constant"):
            self.take()
            names = [self.take()[1]]
            while self.isop(","):
                self.take()
                names.append(self.take()[1])
            # skip type until '=' or ';'
            depth = 0
            while True:
                t2 = self.peek()
                if t2[0] == "eof":
                    return
                if t2[0] == "op" and t2[1] in "([{":
                    depth += 1
                elif t2[0] == "op" and t2[1] in ")]}":
                    depth -= 1
                elif depth == 0 and t2 == ("op", "="):
                    break
                elif depth == 0 and t2 == ("op", ";"):
                    break
                self.take()
            if self.isop("="):
                self.take()
                try:
                    v = self.expr()
                except SyntaxError:
                    self.skip_to_semi()
                    for n in names:
                        self.env[n] = UNKNOWN
                    return
                if execute:
                    for n in names:
                        self.env[n] = v
                if self.isop(";"):
                    self.take()
                else:
                    self.skip_to_semi()
                    if execute:
                        for n in names:
                            self.env[n] = UNKNOWN
            else:
                self.take()
                for n in names:
                    self.env.setdefault(n, UNKNOWN)
            return
        if tk == ("id", "EndOfDecode"):
            self.take()
            self.expect_op("(")
            kind = self.take()[1]
            self.expect_op(")")
            self.expect_op(";")
            if execute:
                raise EndDecode(kind)
            return
        if tk[0] == "id" and tk[1] in ("for", "while", "repeat", "begin"):
            # skip block to matching end;
            self.take()
            depth = 1
            while depth > 0:
                t2 = self.take()
                if t2[0] == "eof":
                    return
                if t2[0] == "id" and t2[1] in ("if", "case", "for", "while", "begin"):
                    depth += 1
                elif t2 == ("id", "end"):
                    depth -= 1
            if self.isop(";"):
                self.take()
            return
        # assignment or expression statement
        if tk[0] == "id" and self.isop("=", 1):
            name = self.take()[1]
            self.take()
            try:
                v = self.expr()
                self.expect_op(";")
            except SyntaxError:
                self.skip_to_semi()
                v = UNKNOWN
            if execute:
                self.env[name] = v
            return
        # generic `lhs = rhs;` (e.g. tuple assignment): evaluate rhs for
        # its decode-time side effects (DecodeBitMasks UNDEF checks).
        j = self.i
        depth = 0
        eq = None
        while True:
            t2 = self.t[j]
            if t2[0] == "eof":
                break
            if t2[0] == "op" and t2[1] in "([{":
                depth += 1
            elif t2[0] == "op" and t2[1] in ")]}":
                depth -= 1
            elif t2 == ("op", ";") and depth <= 0:
                break
            elif t2 == ("op", "=") and depth == 0 and eq is None:
                eq = j
            j += 1
        if eq is not None and execute:
            self.i = eq + 1
            try:
                self.expr()
            except SyntaxError:
                pass
            self.i = j
            if self.isop(";"):
                self.take()
            return
        self.skip_to_semi()

    def branch_body(self, run, unknown):
        """Execute a statement list; if `unknown`, record any EndOfDecode
        inside it as a possibility instead of executing."""
        if run:
            self.stmts(execute=True)
        else:
            start = self.i
            self.stmts(execute=False)
            if unknown:
                body = self.t[start:self.i]
                if ("id", "EndOfDecode") in body:
                    self.saw_unknown_end = True

    # ---- expressions ----
    def truth(self, v):
        if v is UNKNOWN:
            return UNKNOWN
        if isinstance(v, bool):
            return v
        if isinstance(v, Bits) and v.w == 1:
            return v.v == 1
        return UNKNOWN

    def expr(self):
        return self.e_or()

    def e_or(self):
        a = self.e_and()
        while self.isop("||"):
            self.take()
            b = self.e_and()
            ta, tb = self.truth(a), self.truth(b)
            if ta is True or tb is True:
                a = True
            elif ta is UNKNOWN or tb is UNKNOWN:
                a = UNKNOWN
            else:
                a = False
        return a

    def e_and(self):
        a = self.e_cmp()
        while self.isop("&&"):
            self.take()
            b = self.e_cmp()
            ta, tb = self.truth(a), self.truth(b)
            if ta is False or tb is False:
                a = False
            elif ta is UNKNOWN or tb is UNKNOWN:
                a = UNKNOWN
            else:
                a = True
        return a

    def e_cmp(self):
        a = self.e_cat()
        if self.isid("as"):
            self.take()
            # skip a type: identifier, integer{...} or bits(...)
            self.take()
            if self.isop("{") or self.isop("("):
                close = "}" if self.isop("{") else ")"
                depth = 0
                while True:
                    t2 = self.take()
                    if t2[0] == "op" and t2[1] in "({":
                        depth += 1
                    elif t2[0] == "op" and t2[1] in ")}":
                        depth -= 1
                        if depth == 0:
                            break
                    elif t2[0] == "eof":
                        break
        while True:
            if self.isop("==") or self.isop("!="):
                op = self.take()[1]
                b = self.e_cat()
                r = self.eq(a, b)
                if op == "!=" and r is not UNKNOWN:
                    r = not r
                a = r
            elif self.isop("<") or self.isop(">") or self.isop("<=") or self.isop(">="):
                op = self.take()[1]
                b = self.e_cat()
                x, y = self.num(a), self.num(b)
                if x is UNKNOWN or y is UNKNOWN:
                    a = UNKNOWN
                else:
                    a = {"<": x < y, ">": x > y, "<=": x <= y, ">=": x >= y}[op]
            elif self.isid("IN"):
                self.take()
                self.expect_op("{")
                items = []
                while not self.isop("}"):
                    items.append(self.e_cat())
                    if self.isop(","):
                        self.take()
                self.expect_op("}")
                res = False
                for it in items:
                    r = self.eq(a, it)
                    if r is True:
                        res = True
                        break
                    if r is UNKNOWN:
                        res = UNKNOWN
                a = res
            else:
                return a

    def e_cat(self):
        a = self.e_add()
        while self.isop("::"):
            self.take()
            b = self.e_add()
            if isinstance(a, Bits) and isinstance(b, Bits):
                a = Bits((a.v << b.w) | b.v, a.w + b.w)
            else:
                a = UNKNOWN
        return a

    def e_add(self):
        a = self.e_mul()
        while self.isop("+") or self.isop("-") or self.isid("OR") or self.isid("EOR") or self.isid("XOR"):
            op = self.take()[1]
            b = self.e_mul()
            x, y = self.num(a), self.num(b)
            if op in ("OR", "EOR", "XOR") and isinstance(a, Bits) and isinstance(b, Bits):
                a = Bits(a.v | b.v if op == "OR" else a.v ^ b.v, a.w)
            elif x is UNKNOWN or y is UNKNOWN or not isinstance(a, int) or not isinstance(b, int):
                a = UNKNOWN
            else:
                a = x + y if op == "+" else x - y
        return a

    def e_mul(self):
        a = self.e_unary()
        while self.isop("*") or self.isid("DIV") or self.isid("MOD") or self.isid("AND") or self.isop("<<") or self.isop(">>"):
            op = self.take()[1]
            b = self.e_unary()
            if op == "AND" and isinstance(a, Bits) and isinstance(b, Bits):
                a = Bits(a.v & b.v, a.w)
                continue
            if not isinstance(a, int) or not isinstance(b, int) or isinstance(a, bool) or isinstance(b, bool):
                a = UNKNOWN
                continue
            if op == "*":
                a = a * b
            elif op == "DIV":
                a = a // b if b else UNKNOWN
            elif op == "MOD":
                a = a % b if b else UNKNOWN
            elif op == "<<":
                a = a << b
            elif op == ">>":
                a = a >> b
        return a

    def e_unary(self):
        if self.isop("!") or self.isid("NOT"):
            self.take()
            v = self.e_unary()
            if isinstance(v, Bits) and v.w != 1:
                return Bits(~v.v, v.w)
            t = self.truth(v)
            return UNKNOWN if t is UNKNOWN else (not t)
        if self.isop("-"):
            self.take()
            v = self.e_unary()
            return -v if isinstance(v, int) and not isinstance(v, bool) else UNKNOWN
        return self.e_post()

    def e_post(self):
        v = self.e_prim()
        while self.isop("["):
            self.take()
            idxs = []
            while not self.isop("]"):
                hi = self.expr()
                if self.isop(":"):
                    self.take()
                    lo = self.expr()
                    idxs.append((hi, lo))
                elif self.isop("+:"):
                    self.take()
                    wd = self.expr()
                    if isinstance(hi, int) and isinstance(wd, int):
                        idxs.append((hi + wd - 1, hi))
                    else:
                        idxs.append((UNKNOWN, UNKNOWN))
                else:
                    idxs.append((hi, hi))
                if self.isop(","):
                    self.take()
            self.expect_op("]")
            if not isinstance(v, Bits):
                v = UNKNOWN
                continue
            res = Bits(0, 0)
            for hi, lo in idxs:
                if not isinstance(hi, int) or not isinstance(lo, int):
                    res = UNKNOWN
                    break
                w = hi - lo + 1
                res = Bits((res.v << w) | ((v.v >> lo) & ((1 << w) - 1)), res.w + w)
            v = res
        return v

    def args(self):
        self.expect_op("(")
        out = []
        while not self.isop(")"):
            out.append(self.expr())
            if self.isop(","):
                self.take()
            elif not self.isop(")"):
                raise SyntaxError("bad argument list")
        self.expect_op(")")
        return out

    def e_prim(self):
        tk = self.take()
        if tk[0] == "bits":
            s = tk[1]
            if "x" in s:
                return Pat(s)
            return Bits(int(s, 2) if s else 0, len(s))
        if tk[0] == "num":
            return tk[1]
        if tk[0] == "str":
            return UNKNOWN
        if tk == ("op", "("):
            v = self.expr()
            if self.isop(","):
                while not self.isop(")"):
                    self.take()
                v = UNKNOWN
            self.expect_op(")")
            return v
        if tk == ("op", "{"):
            depth = 1
            while depth:
                t2 = self.take()
                if t2 == ("op", "{"):
                    depth += 1
                elif t2 == ("op", "}"):
                    depth -= 1
                elif t2[0] == "eof":
                    break
            return UNKNOWN
        if tk == ("id", "if"):
            c = self.truth(self.expr())
            self.expect_id("then")
            a = self.expr()
            res = a if c is True else (UNKNOWN if c is UNKNOWN else None)
            while self.isid("elsif"):
                self.take()
                c2 = self.truth(self.expr())
                self.expect_id("then")
                b = self.expr()
                if res is None:
                    res = b if c2 is True else (UNKNOWN if c2 is UNKNOWN else None)
            self.expect_id("else")
            e = self.expr()
            return e if res is None else res
        if tk[0] == "id":
            name = tk[1]
            if name == "TRUE":
                return True
            if name == "FALSE":
                return False
            # generic instantiation f{N}(...)
            if self.isop("{") and name[0].isupper():
                depth = 0
                while True:
                    t2 = self.take()
                    if t2 == ("op", "{"):
                        depth += 1
                    elif t2 == ("op", "}"):
                        depth -= 1
                        if depth == 0:
                            break
                    elif t2[0] == "eof":
                        break
            if self.isop("("):
                a = self.args()
                return self.call(name, a)
            if name in self.env:
                return self.env[name]
            return UNKNOWN
        raise SyntaxError("unexpected %r" % (tk,))

    def call(self, name, a):
        if name == "DecodeBitMasks" and len(a) >= 4 and all(isinstance(v, Bits) for v in a[:3]):
            immn, imms, immr = a[0], a[1], a[2]
            comb = (immn.v << 6) | (~imms.v & 0x3F)
            ln = comb.bit_length() - 1
            if ln < 1:
                raise EndDecode("Decode_UNDEF")
            levels = (1 << ln) - 1
            if a[3] is True and (imms.v & levels) == levels:
                raise EndDecode("Decode_UNDEF")
            return UNKNOWN
        if name == "IsFeatureImplemented":
            return UNKNOWN if not a or a[0] is UNKNOWN else a[0]
        if name == "UInt":
            return a[0].v if a and isinstance(a[0], Bits) else UNKNOWN
        if name == "SInt":
            if a and isinstance(a[0], Bits) and a[0].w:
                b = a[0]
                return b.v - (1 << b.w) if (b.v >> (b.w - 1)) & 1 else b.v
            return UNKNOWN
        if name in ("Zeros", "Ones") and a and isinstance(a[0], int):
            return Bits(0 if name == "Zeros" else -1, a[0])
        if name == "IsZero" and a and isinstance(a[0], Bits):
            return a[0].v == 0
        if name == "IsOnes" and a and isinstance(a[0], Bits):
            return a[0].v == (1 << a[0].w) - 1
        if name == "HighestSetBit" and a and isinstance(a[0], Bits):
            return a[0].v.bit_length() - 1
        if name == "ZeroExtend" and len(a) == 2 and isinstance(a[0], Bits) and isinstance(a[1], int):
            return Bits(a[0].v, a[1])
        if name == "ZeroExtend" and len(a) == 1 and isinstance(a[0], Bits):
            return UNKNOWN
        return UNKNOWN

    def num(self, v):
        if isinstance(v, bool):
            return UNKNOWN
        if isinstance(v, int):
            return v
        return UNKNOWN

    def eq(self, a, b):
        if a is UNKNOWN or b is UNKNOWN:
            return UNKNOWN
        if isinstance(b, Pat) and isinstance(a, Bits):
            return b.match(a)
        if isinstance(a, Pat) and isinstance(b, Bits):
            return a.match(b)
        if isinstance(a, Bits) and isinstance(b, Bits):
            return a.v == b.v
        if isinstance(a, bool) and isinstance(b, bool):
            return a == b
        if isinstance(a, int) and isinstance(b, int) and not isinstance(a, bool) and not isinstance(b, bool):
            return a == b
        if isinstance(a, str) and isinstance(b, str):
            return a == b
        return UNKNOWN


def evaluate(decode_text, fields, word, features):
    """Return 'OK', 'UNDEF', 'NOP' or 'UNKNOWN' for this word."""
    env = {}
    for name, (hi, lo) in fields.items():
        w = hi - lo + 1
        env[name] = Bits((word >> lo) & ((1 << w) - 1), w)
    for f in ALL_FEATURES_SEEN:
        env[f] = f in features
    try:
        toks = tokenize(decode_text)
    except SyntaxError:
        return "UNKNOWN"
    it = Interp(toks, env, features)
    # FEAT_* identifiers resolve to booleans
    for tk in toks:
        if tk[0] == "id" and tk[1].startswith("FEAT_"):
            env.setdefault(tk[1], tk[1] in features)
    try:
        it.run()
    except EndDecode as e:
        if e.kind == "Decode_UNDEF":
            return "UNDEF"
        if e.kind == "Decode_NOP":
            return "NOP"
        return "UNKNOWN"
    except (SyntaxError, IndexError, RecursionError):
        return "UNKNOWN"
    if it.saw_unknown_end:
        return "UNKNOWN"
    return "OK"


ALL_FEATURES_SEEN = set()


def eval_feature_expr(expr, features):
    """Evaluate an arch_variant feature expression like 'FEAT_A && FEAT_B'."""
    toks = tokenize(expr)
    env = {}
    for tk in toks:
        if tk[0] == "id" and tk[1].startswith("FEAT_"):
            env[tk[1]] = tk[1] in features
    it = Interp(toks, env, features)
    try:
        v = it.expr()
    except SyntaxError:
        return UNKNOWN
    return it.truth(v)
