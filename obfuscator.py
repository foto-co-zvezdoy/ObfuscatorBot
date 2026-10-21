#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Текстовая обфускация Python-кода (без компиляции в бинарники).

Общие слои:
  1. Name mangling  - переименование переменных/функций/классов/аргументов в _O0O0..
  2. String crypto  - все строки -> base64 -> hex -> таблица + декодер.
  3. Minify + junk  - комментарии/пустые строки исчезают (сборка из AST) + мусор.
  4. Marshal wrap   - compile+marshal -> zlib -> XOR -> hex.

Режимы:
  plain  - self-extracting скрипт: данные после '# === DATA START ===',
           чтение через __file__, анти-хук/анти-дебаг, exec в RAM.
  hikka  - модуль Hikka/FTG: видимый маскировочный класс с пустыми командами,
           логика после '# === ENCRYPTED LOGIC ===', подмена методов
           в client_ready, проверка легитимности загрузчика Hikka.

Использование:
  python3 obfuscator.py input.txt output.txt --mode plain|hikka [--preserve a,b]
"""
import ast
import sys
import os
import random
import secrets
import base64
import zlib
import marshal
import argparse

sys.setrecursionlimit(200000)
ALPHABET = 'O0'


# ---------------------------------------------------------------------------
# Scope model
# ---------------------------------------------------------------------------
class Scope:
    __slots__ = ('kind', 'parent', 'node', 'bindings', 'globals', 'nonlocals', 'renames')

    def __init__(self, kind, parent=None, node=None):
        self.kind = kind
        self.parent = parent
        self.node = node
        self.bindings = set()
        self.globals = set()
        self.nonlocals = set()
        self.renames = {}


class Ctx:
    def __init__(self):
        self.scopes = []
        self.module = None
        self.name_nodes = []     # (Name, scope)
        self.arg_nodes = []      # (arg, funcscope)
        self.alias_nodes = []    # (alias, scope, bound)
        self.def_nodes = []      # (FunctionDef/ClassDef, scope)
        self.decl_nodes = []     # (Global/Nonlocal, scope)
        self.except_nodes = []   # (ExceptHandler, scope)
        self.match_nodes = []    # (obj, attr, scope)
        self.kwarg_names = set()
        self.no_rename = set()
        self.all_names = set()
        self.mangling_ok = True
        self.counter = random.getrandbits(20)
        self.salt = random.getrandbits(48)


def iter_scopes(scope):
    while scope is not None:
        yield scope
        scope = scope.parent


def gen_name(ctx):
    """Уникальное имя только из O/0. Счётчик гарантирует отсутствие коллизий
    при любом размере файла, соль делает вид случайным."""
    while True:
        n = ctx.counter
        ctx.counter += 1
        bits = max(6, n.bit_length(), ctx.salt.bit_length()) + 1
        length = bits + random.randint(0, 3)
        val = n ^ ctx.salt
        name = '_' + ''.join('O' if not (val >> i) & 1 else '0' for i in range(length))
        if name not in ctx.all_names and name not in ctx.kwarg_names:
            ctx.all_names.add(name)
            return name


def bind_name(name, scope, ctx, node=None):
    tscope = scope
    for s in iter_scopes(scope):
        if name in s.globals:
            tscope = ctx.module
            break
        if name in s.nonlocals:
            p = s.parent
            found = None
            while p is not None:
                if p.kind in ('function', 'lambda') and name in p.bindings:
                    found = p
                    break
                p = p.parent
            tscope = found or s
            break
    tscope.bindings.add(name)
    if node is not None:
        ctx.name_nodes.append((node, tscope))


def resolve(name, scope, ctx):
    for s in iter_scopes(scope):
        if name in s.globals:
            return ctx.module if name in ctx.module.bindings else None
        if name in s.nonlocals:
            p = s.parent
            while p is not None:
                if p.kind in ('function', 'lambda') and name in p.bindings:
                    return p
                p = p.parent
            return None
    s = scope
    while s is not None:
        if s.kind == 'class':
            if s is scope and name in s.bindings:
                return s
        elif name in s.bindings:
            return s
        s = s.parent
    return None


def should_rename(name, ctx):
    if not ctx.mangling_ok:
        return False
    if name in ctx.no_rename or name in ctx.kwarg_names:
        return False
    if name.startswith('__') and name.endswith('__'):
        return False
    return True


# ---------------------------------------------------------------------------
# Обход дерева: сбор привязок и областей видимости
# ---------------------------------------------------------------------------
def prescan_decls(body, scope):
    """Собрать global/nonlocal на верхнем уровне области (не заходя во вложенные)."""
    for st in body:
        if isinstance(st, ast.Global):
            scope.globals.update(st.names)
        elif isinstance(st, ast.Nonlocal):
            scope.nonlocals.update(st.names)
        elif isinstance(st, (ast.If, ast.While)):
            prescan_decls(st.body, scope)
            prescan_decls(st.orelse, scope)
        elif isinstance(st, (ast.For, ast.AsyncFor)):
            prescan_decls(st.body, scope)
            prescan_decls(st.orelse, scope)
        elif isinstance(st, (ast.With, ast.AsyncWith)):
            prescan_decls(st.body, scope)
        elif isinstance(st, ast.Try):
            prescan_decls(st.body, scope)
            for h in st.handlers:
                prescan_decls(h.body, scope)
            prescan_decls(st.orelse, scope)
            prescan_decls(st.finalbody, scope)


def bind_target(t, scope, ctx):
    if isinstance(t, ast.Name):
        bind_name(t.id, scope, ctx, t)
    elif isinstance(t, ast.Starred):
        bind_target(t.value, scope, ctx)
    elif isinstance(t, (ast.Tuple, ast.List)):
        for e in t.elts:
            bind_target(e, scope, ctx)
    else:
        scan_expr(t, scope, ctx)


def scan_params(args, fscope, outer, ctx):
    for a in list(args.posonlyargs) + list(args.args) + list(args.kwonlyargs):
        fscope.bindings.add(a.arg)
        ctx.arg_nodes.append((a, fscope))
        if a.annotation:
            scan_expr(a.annotation, outer, ctx)
    for a in (args.vararg, args.kwarg):
        if a is not None:
            fscope.bindings.add(a.arg)
            ctx.arg_nodes.append((a, fscope))
            if a.annotation:
                scan_expr(a.annotation, outer, ctx)
    for d in list(args.defaults):
        scan_expr(d, outer, ctx)
    for d in list(args.kw_defaults):
        if d is not None:
            scan_expr(d, outer, ctx)


def scan_expr(node, scope, ctx):
    if node is None:
        return
    if isinstance(node, ast.Name):
        ctx.name_nodes.append((node, scope))
        return
    if isinstance(node, ast.Lambda):
        new = Scope('lambda', scope, node)
        ctx.scopes.append(new)
        scan_params(node.args, new, scope, ctx)
        scan_expr(node.body, new, ctx)
        return
    if isinstance(node, (ast.ListComp, ast.SetComp, ast.GeneratorExp, ast.DictComp)):
        new = Scope('comp', scope, node)
        ctx.scopes.append(new)
        for i, gen in enumerate(node.generators):
            scan_expr(gen.iter, scope if i == 0 else new, ctx)
            bind_target(gen.target, new, ctx)
            for cond in gen.ifs:
                scan_expr(cond, new, ctx)
        if isinstance(node, ast.DictComp):
            scan_expr(node.key, new, ctx)
            scan_expr(node.value, new, ctx)
        else:
            scan_expr(node.elt, new, ctx)
        return
    if isinstance(node, ast.NamedExpr):
        scan_expr(node.value, scope, ctx)
        bs = scope
        while bs is not None and bs.kind == 'comp':
            bs = bs.parent
        bind_target(node.target, bs or scope, ctx)
        return
    for child in ast.iter_child_nodes(node):
        if isinstance(child, ast.keyword) and child.arg is not None:
            ctx.kwarg_names.add(child.arg)
        scan_expr(child, scope, ctx)


def visit_body(body, scope, ctx):
    for st in body:
        visit_stmt(st, scope, ctx)


def visit_stmt(st, scope, ctx):
    if isinstance(st, (ast.FunctionDef, ast.AsyncFunctionDef)):
        scope.bindings.add(st.name)
        ctx.def_nodes.append((st, scope))
        for d in st.decorator_list:
            scan_expr(d, scope, ctx)
        if st.returns:
            scan_expr(st.returns, scope, ctx)
        new = Scope('function', scope, st)
        ctx.scopes.append(new)
        scan_params(st.args, new, scope, ctx)
        prescan_decls(st.body, new)
        visit_body(st.body, new, ctx)
        return
    if isinstance(st, ast.ClassDef):
        scope.bindings.add(st.name)
        ctx.def_nodes.append((st, scope))
        for d in st.decorator_list:
            scan_expr(d, scope, ctx)
        for b in st.bases:
            scan_expr(b, scope, ctx)
        for k in st.keywords:
            scan_expr(k.value, scope, ctx)
        new = Scope('class', scope, st)
        ctx.scopes.append(new)
        prescan_decls(st.body, new)
        visit_body(st.body, new, ctx)
        return
    if isinstance(st, ast.Import):
        for a in st.names:
            bound = a.asname or a.name.split('.')[0]
            bind_name(bound, scope, ctx)
            if a.asname is None and '.' in a.name:
                ctx.no_rename.add(bound)
            else:
                ctx.alias_nodes.append((a, scope, bound))
        return
    if isinstance(st, ast.ImportFrom):
        for a in st.names:
            if a.name == '*':
                ctx.mangling_ok = False
            else:
                bound = a.asname or a.name
                bind_name(bound, scope, ctx)
                if st.module == '__future__':
                    ctx.no_rename.add(bound)
                else:
                    ctx.alias_nodes.append((a, scope, bound))
        return
    if isinstance(st, ast.Global):
        scope.globals.update(st.names)
        ctx.decl_nodes.append((st, scope))
        return
    if isinstance(st, ast.Nonlocal):
        scope.nonlocals.update(st.names)
        ctx.decl_nodes.append((st, scope))
        return
    if isinstance(st, ast.Assign):
        scan_expr(st.value, scope, ctx)
        for t in st.targets:
            bind_target(t, scope, ctx)
        return
    if isinstance(st, ast.AnnAssign):
        if st.annotation:
            scan_expr(st.annotation, scope, ctx)
        if st.value:
            scan_expr(st.value, scope, ctx)
        bind_target(st.target, scope, ctx)
        return
    if isinstance(st, ast.AugAssign):
        scan_expr(st.value, scope, ctx)
        bind_target(st.target, scope, ctx)
        return
    if isinstance(st, (ast.For, ast.AsyncFor)):
        scan_expr(st.iter, scope, ctx)
        bind_target(st.target, scope, ctx)
        visit_body(st.body, scope, ctx)
        visit_body(st.orelse, scope, ctx)
        return
    if isinstance(st, (ast.With, ast.AsyncWith)):
        for it in st.items:
            scan_expr(it.context_expr, scope, ctx)
            if it.optional_vars:
                bind_target(it.optional_vars, scope, ctx)
        visit_body(st.body, scope, ctx)
        return
    if isinstance(st, ast.Try) or type(st).__name__ == 'TryStar':
        visit_body(st.body, scope, ctx)
        for h in st.handlers:
            if h.type:
                scan_expr(h.type, scope, ctx)
            if h.name:
                bind_name(h.name, scope, ctx)
                ctx.except_nodes.append((h, scope))
            visit_body(h.body, scope, ctx)
        visit_body(st.orelse, scope, ctx)
        visit_body(st.finalbody, scope, ctx)
        return
    if isinstance(st, ast.If) or isinstance(st, ast.While):
        scan_expr(st.test, scope, ctx)
        visit_body(st.body, scope, ctx)
        visit_body(st.orelse, scope, ctx)
        return
    if type(st).__name__ == 'Match':
        scan_expr(st.subject, scope, ctx)
        for case in st.cases:
            scan_pattern(case.pattern, scope, ctx)
            if case.guard:
                scan_expr(case.guard, scope, ctx)
            visit_body(case.body, scope, ctx)
        return
    for child in ast.iter_child_nodes(st):
        scan_expr(child, scope, ctx)


def scan_pattern(p, scope, ctx):
    if p is None:
        return
    if isinstance(p, ast.MatchAs):
        if p.name:
            bind_name(p.name, scope, ctx)
            ctx.match_nodes.append((p, 'name', scope))
        scan_pattern(p.pattern, scope, ctx)
    elif isinstance(p, ast.MatchStar):
        if p.name:
            bind_name(p.name, scope, ctx)
            ctx.match_nodes.append((p, 'name', scope))
    elif isinstance(p, ast.MatchMapping):
        for k in p.keys:
            scan_expr(k, scope, ctx)
        for sp in p.patterns:
            scan_pattern(sp, scope, ctx)
        if p.rest:
            bind_name(p.rest, scope, ctx)
            ctx.match_nodes.append((p, 'rest', scope))
    elif isinstance(p, ast.MatchClass):
        scan_expr(p.cls, scope, ctx)
        for sp in p.patterns:
            scan_pattern(sp, scope, ctx)
        for sp in p.kwd_patterns:
            scan_pattern(sp, scope, ctx)
    elif isinstance(p, ast.MatchSequence):
        for sp in p.patterns:
            scan_pattern(sp, scope, ctx)
    elif isinstance(p, ast.MatchOr):
        for sp in p.patterns:
            scan_pattern(sp, scope, ctx)
    elif isinstance(p, ast.MatchValue):
        scan_expr(p.value, scope, ctx)


# ---------------------------------------------------------------------------
# Применение переименования
# ---------------------------------------------------------------------------
def compute_renames(ctx):
    for scope in ctx.scopes:
        if scope.kind == 'class':
            # Имена в теле класса становятся атрибутами (obj.method / obj.attr),
            # доступ к ним идёт по исходной строке -> переименовывать нельзя.
            continue
        for name in sorted(scope.bindings):
            if should_rename(name, ctx):
                scope.renames[name] = gen_name(ctx)


def apply_renames(ctx):
    for node, scope in ctx.name_nodes:
        b = resolve(node.id, scope, ctx)
        if b is not None and node.id in b.renames:
            node.id = b.renames[node.id]
    for a, fscope in ctx.arg_nodes:
        if a.arg in fscope.renames:
            a.arg = fscope.renames[a.arg]
    for st, scope in ctx.def_nodes:
        b = resolve(st.name, scope, ctx)
        if b is not None and st.name in b.renames:
            st.name = b.renames[st.name]
    for al, scope, bound in ctx.alias_nodes:
        b = resolve(bound, scope, ctx)
        if b is not None and bound in b.renames:
            al.asname = b.renames[bound]
    for st, scope in ctx.decl_nodes:
        out = []
        for nm in st.names:
            b = None
            if isinstance(st, ast.Global):
                b = ctx.module if nm in ctx.module.bindings else None
            else:
                p = scope.parent
                while p is not None:
                    if p.kind in ('function', 'lambda') and nm in p.bindings:
                        b = p
                        break
                    p = p.parent
            out.append(b.renames.get(nm, nm) if b else nm)
        st.names = out
    for h, scope in ctx.except_nodes:
        if h.name:
            b = resolve(h.name, scope, ctx)
            if b is not None and h.name in b.renames:
                h.name = b.renames[h.name]
    for obj, attr, scope in ctx.match_nodes:
        nm = getattr(obj, attr)
        if nm:
            b = resolve(nm, scope, ctx)
            if b is not None and nm in b.renames:
                setattr(obj, attr, b.renames[nm])


def collect_all_names(tree, ctx):
    for n in ast.walk(tree):
        for f in ('id', 'name', 'arg', 'attr', 'rest'):
            v = getattr(n, f, None)
            if isinstance(v, str):
                ctx.all_names.add(v)
        if isinstance(n, ast.alias):
            ctx.all_names.add(n.name.split('.')[0])
            if n.asname:
                ctx.all_names.add(n.asname)
        if isinstance(n, (ast.Global, ast.Nonlocal)):
            ctx.all_names.update(n.names)
        if isinstance(n, ast.keyword) and n.arg:
            ctx.kwarg_names.add(n.arg)


def detect_dynamic_and_all(tree, ctx):
    for n in ast.walk(tree):
        if isinstance(n, ast.Name) and n.id in ('globals', 'locals', 'vars', 'eval', 'exec'):
            ctx.mangling_ok = False
        if isinstance(n, ast.Assign):
            for t in n.targets:
                if isinstance(t, ast.Name) and t.id == '__all__':
                    val = n.value
                    if isinstance(val, (ast.List, ast.Tuple, ast.Set)):
                        for e in val.elts:
                            if isinstance(e, ast.Constant) and isinstance(e.value, str):
                                ctx.no_rename.add(e.value)


# ---------------------------------------------------------------------------
# Уровень 2: шифрование строк
# ---------------------------------------------------------------------------
class StringCrypto(ast.NodeTransformer):
    def __init__(self, ctx):
        self.table = []
        self.cache = {}
        self.s_name = gen_name(ctx)
        self.b_name = gen_name(ctx)
        self.imp = gen_name(ctx)
        self.t_name = gen_name(ctx)

    def _enc(self, raw):
        hx = base64.b64encode(raw).hex()
        if hx not in self.cache:
            self.cache[hx] = len(self.table)
            self.table.append(hx)
        return self.cache[hx]

    def _call(self, name, idx):
        return ast.Call(func=ast.Name(id=name, ctx=ast.Load()),
                        args=[ast.Constant(value=idx)], keywords=[])

    def _dec_str(self, idx):
        return ast.Call(
            func=ast.Attribute(value=self._call(self.b_name, idx), attr='decode', ctx=ast.Load()),
            args=[ast.Constant(value='utf-8')], keywords=[])

    def visit_Constant(self, node):
        v = node.value
        if isinstance(v, str):
            if v == '':
                return node
            return self._dec_str(self._enc(v.encode('utf-8')))
        if isinstance(v, bytes):
            if v == b'':
                return node
            return self._call(self.b_name, self._enc(v))
        return node

    def visit_JoinedStr(self, node):
        vals = []
        for v in node.values:
            if isinstance(v, ast.Constant) and isinstance(v.value, str):
                if v.value == '':
                    vals.append(v)
                else:
                    vals.append(ast.FormattedValue(value=self._dec_str(self._enc(v.value.encode('utf-8'))),
                                                   conversion=-1, format_spec=None))
            elif isinstance(v, ast.FormattedValue):
                vals.append(ast.FormattedValue(value=self.visit(v.value),
                                               conversion=v.conversion, format_spec=v.format_spec))
            else:
                vals.append(self.visit(v))
        node.values = vals
        return node

    def visit_MatchValue(self, node):
        return node

    def visit_MatchMapping(self, node):
        node.patterns = [self.visit(p) for p in node.patterns]
        return node


def inject_decoder(tree, c):
    prelude = [ast.Import(names=[ast.alias(name='base64', asname=c.imp)])]
    prelude.append(ast.Assign(targets=[ast.Name(id=c.t_name, ctx=ast.Store())],
                              value=ast.List(elts=[ast.Constant(value=h) for h in c.table],
                                             ctx=ast.Load())))

    def dec(name, is_str):
        sub = ast.Subscript(value=ast.Name(id=c.t_name, ctx=ast.Load()),
                            slice=ast.Name(id='i', ctx=ast.Load()), ctx=ast.Load())
        call = ast.Call(func=ast.Attribute(value=ast.Name(id=c.imp, ctx=ast.Load()),
                                           attr='b64decode', ctx=ast.Load()),
                        args=[ast.Call(func=ast.Attribute(value=ast.Name(id='bytes', ctx=ast.Load()),
                                                          attr='fromhex', ctx=ast.Load()),
                                       args=[sub], keywords=[])], keywords=[])
        if is_str:
            call = ast.Call(func=ast.Attribute(value=call, attr='decode', ctx=ast.Load()),
                            args=[ast.Constant(value='utf-8')], keywords=[])
        args = ast.arguments(posonlyargs=[], args=[ast.arg(arg='i')], vararg=None,
                             kwonlyargs=[], kw_defaults=[], kwarg=None, defaults=[])
        return ast.FunctionDef(name=name, args=args, body=[ast.Return(value=call)],
                               decorator_list=[])

    prelude.append(dec(c.b_name, False))
    prelude.append(dec(c.s_name, True))
    tree.body = prelude + tree.body
    return tree


# ---------------------------------------------------------------------------
# Уровень 3: мусорный код
# ---------------------------------------------------------------------------
def junk_stmts(ctx, n=1):
    out = []
    for _ in range(n):
        a, b, cc = gen_name(ctx), gen_name(ctx), gen_name(ctx)
        src = (f"{a} = [{b} for {b} in range(0)]\n"
               f"for {cc} in range(0):\n"
               f"    {a} = {a} + []\n")
        out.extend(ast.parse(src).body)
    return out


def inject_junk(tree, ctx):
    funcs = [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
    tree.body = junk_stmts(ctx) + tree.body
    for f in funcs:
        f.body = junk_stmts(ctx) + f.body
    return tree


# ---------------------------------------------------------------------------
# Уровень 4: обёртка marshal + exec
# ---------------------------------------------------------------------------
def transform_tree(tree, filename, preserve=(), do_rename=True,
                   do_strings=True, do_junk=True):
    ctx = Ctx()
    collect_all_names(tree, ctx)
    ctx.no_rename.update(preserve)
    detect_dynamic_and_all(tree, ctx)
    if not do_rename:
        ctx.mangling_ok = False

    module = Scope('module', None, tree)
    ctx.module = module
    ctx.scopes.append(module)
    prescan_decls(tree.body, module)
    visit_body(tree.body, module, ctx)

    if ctx.mangling_ok:
        compute_renames(ctx)
        apply_renames(ctx)

    if do_strings:
        crypto = StringCrypto(ctx)
        tree = crypto.visit(tree)
        inject_decoder(tree, crypto)
    if do_junk:
        inject_junk(tree, ctx)

    ast.fix_missing_locations(tree)
    return tree, ctx


def compile_tree(tree, filename):
    return compile(tree, filename, 'exec')


def xor_bytes(data, key):
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def key_exprs(key):
    """64 случайных математических выражения, дающих байты XOR-ключа.

    При каждой обфускации заново выбираются и коэффициенты, и форма выражения
    (3 базовых шаблона + необязательный XOR). Каждое выражение проверяется
    на точное совпадение с байтом ключа.
    """
    out = []
    for t in key:
        a = secrets.randbelow(250) + 2
        b = secrets.randbelow(250) + 2

        shape = secrets.randbelow(3)
        if shape == 0:
            base = a * b
            head = f'{a}*{b}'
        elif shape == 1:
            base = a * (b + 1)
            head = f'{a}*({b}+1)'
        else:
            base = a * b + a
            head = f'({a}*{b}+{a})'

        if secrets.randbelow(2):
            d = secrets.randbelow(256)
            c = ((t ^ d) - base) % 256
            expr = f'(({head}+{c})^{d})%256'
            val = ((base + c) ^ d) % 256
        else:
            c = (t - base) % 256
            expr = f'({head}+{c})%256'
            val = (base + c) % 256

        if val != t:
            raise RuntimeError(f'key expression mismatch: {val} != {t}')
        out.append(expr)

    assert len(out) == len(key)
    return out


def pack_payload(code, key):
    """marshal -> zlib -> XOR -> hex."""
    raw = marshal.dumps(code)
    return xor_bytes(zlib.compress(raw, 9), key).hex()


def data_block(hexdata, marker, var='_zz', width=200):
    lines = [marker, f'{var} = (', "'''"]
    lines += [hexdata[i:i + width] for i in range(0, len(hexdata), width)]
    lines += ["'''", ')']
    return '\n'.join(lines) + '\n'


PLAIN_MARKER = '# === DATA START ==='
HIKKA_MARKER = '# === ENCRYPTED LOGIC ==='


def build_plain(data, filename, preserve=(), do_rename=True,
                do_strings=True, do_junk=True):
    tree = ast.parse(data, filename)
    tree, ctx = transform_tree(tree, filename, preserve, do_rename, do_strings, do_junk)
    code = compile_tree(tree, filename)

    # Полностью случайные 64 байта; новые при каждой обфускации.
    key = secrets.token_bytes(64)
    hx = pack_payload(code, key)
    e = key_exprs(key)

    n = {k: gen_name(ctx) for k in
         ('sys', 'os', 'zlib', 'marshal', 'builtins', 'key', 'xor', 'data',
          'mark', 'idx', 'tmp', 'start', 'end', 'depth', 'frame')}
    kl = ',\n    '.join(e)

    loader = f'''import sys as {n['sys']}, os as {n['os']}, zlib as {n['zlib']}, marshal as {n['marshal']}, builtins as {n['builtins']}

{n['key']} = bytes([
    {kl}
])

def {n['xor']}(d):
    return bytes(b ^ {n['key']}[i % 64] for i, b in enumerate(d))

if {n['sys']}.gettrace() is not None or {n['sys']}.getprofile() is not None:
    {n['os']}._exit(1)
if type(getattr({n['builtins']}, 'print', None)).__name__ != 'builtin_function_or_method':
    {n['os']}._exit(1)
if not hasattr({n['sys']}.stdout, 'fileno') or getattr({n['sys']}.stdout, 'write', None) is None:
    {n['os']}._exit(1)
{n['depth']} = 0
{n['frame']} = {n['sys']}._getframe()
while {n['frame']} is not None:
    {n['depth']} += 1
    if 'print' in {n['frame']}.f_code.co_name or 'write' in {n['frame']}.f_code.co_name:
        {n['os']}._exit(1)
    if {n['depth']} > 2000:
        {n['os']}._exit(1)
    {n['frame']} = {n['frame']}.f_back

{n['data']} = open({n['os']}.path.abspath(__file__), 'rb').read()
{n['mark']} = b'{PLAIN_MARKER}'
{n['idx']} = {n['data']}.rfind({n['mark']})
if {n['idx']} < 0:
    {n['os']}._exit(1)
{n['tmp']} = {n['data']}[{n['idx']} + len({n['mark']}):]
{n['start']} = {n['tmp']}.find(b"\\x27\\x27\\x27") + 3
{n['end']} = {n['tmp']}.find(b"\\x27\\x27\\x27", {n['start']})
if {n['start']} < 3 or {n['end']} < 0:
    {n['os']}._exit(1)
exec({n['marshal']}.loads({n['zlib']}.decompress({n['xor']}(bytes.fromhex({n['tmp']}[{n['start']}:{n['end']}].decode())))), globals())
'''
    return loader + '\n' + data_block(hx, PLAIN_MARKER)


# ---------------------------------------------------------------------------
# Режим Hikka/FTG
# ---------------------------------------------------------------------------
def _deco_last(dec):
    try:
        return ast.unparse(dec).split('.')[-1].strip('()')
    except Exception:
        return ''


def find_module_class(tree):
    best = None
    best_score = 0
    for node in tree.body:
        if not isinstance(node, ast.ClassDef):
            continue
        score = 0
        decs = [ast.unparse(d) for d in node.decorator_list]
        bases = [ast.unparse(b) for b in node.bases]
        if any(d.endswith('tds') for d in decs):
            score += 3
        if any('Module' in b for b in bases):
            score += 2
        methods = [x for x in node.body
                   if isinstance(x, (ast.FunctionDef, ast.AsyncFunctionDef))]
        names = [m.name for m in methods]
        if 'client_ready' in names:
            score += 1
        if any(any(_deco_last(d) in ('command', 'inline', 'callback')
                   for d in m.decorator_list) for m in methods):
            score += 3
        if score > best_score:
            best_score = score
            best = node
    return best if best_score > 0 else None


def hikka_analyze(data, filename):
    tree = ast.parse(data, filename)
    cls = find_module_class(tree)
    if cls is None:
        raise ValueError('это не модуль Hikka/FTG: класс loader.Module не найден')

    methods = [x for x in cls.body
               if isinstance(x, (ast.FunctionDef, ast.AsyncFunctionDef))]
    method_names = [m.name for m in methods]
    command_methods = [m for m in methods
                       if any(_deco_last(d) in ('command', 'inline', 'callback')
                              for d in m.decorator_list)]

    strings = None
    for node in cls.body:
        targets = []
        if isinstance(node, ast.Assign):
            targets = node.targets
        elif isinstance(node, ast.AnnAssign):
            targets = [node.target]
        if any(isinstance(t, ast.Name) and t.id == 'strings' for t in targets):
            strings = node.value

    # payload = всё, кроме класса, + методы как обычные функции
    body = [x for x in tree.body if x is not cls]
    payload = ast.Module(body=body + methods, type_ignores=[])
    return {
        'class_name': cls.name,
        'methods': methods,
        'method_names': method_names,
        'command_methods': command_methods,
        'strings': strings,
        'payload_tree': payload,
    }


def build_hikka(data, filename):
    info = hikka_analyze(data, filename)
    cls = info['class_name']

    # ВАЖНО: снимаем видимые заглушки/метаданные ДО transform_tree,
    # иначе он изменит узлы на месте (переименует loader/аргументы).
    strings_src = ast.unparse(info['strings']) if info['strings'] is not None \
        else '{"name": %r}' % cls

    stub_lines = []
    for m in info['command_methods']:
        for d in m.decorator_list:
            stub_lines.append('    @' + ast.unparse(d))
        kw = 'async def' if isinstance(m, ast.AsyncFunctionDef) else 'def'
        stub_lines.append(f'    {kw} {m.name}({ast.unparse(m.args)}):')
        stub_lines.append('        pass')
        stub_lines.append('')
    stubs = '\n'.join(stub_lines)
    names_literal = repr([x for x in info['method_names'] if x != 'client_ready'])

    tree, ctx = transform_tree(info['payload_tree'], filename,
                               preserve=info['method_names'],
                               do_rename=True, do_strings=True, do_junk=True)
    code = compile_tree(tree, filename)

    # Полностью случайные 64 байта; новые при каждой обфускации.
    key = secrets.token_bytes(64)
    hx = pack_payload(code, key)
    e = key_exprs(key)
    kl = ',\n        '.join(e)

    body = f'''# meta developer: @obfuscator
from .. import loader, utils


@loader.tds
class {cls}(loader.Module):
    """{cls}"""

    strings = {strings_src}

{stubs}
    async def client_ready(self, client, db):
        import sys, os, zlib, marshal
        if sys.gettrace() is not None or sys.getprofile() is not None:
            os._exit(1)
        import builtins
        if type(getattr(builtins, 'print', None)).__name__ != 'builtin_function_or_method':
            os._exit(1)
        if not hasattr(sys.stdout, 'fileno') or getattr(sys.stdout, 'write', None) is None:
            os._exit(1)
        _d = 0
        _f = sys._getframe()
        while _f is not None:
            _d += 1
            if 'print' in _f.f_code.co_name or 'write' in _f.f_code.co_name:
                os._exit(1)
            if _d > 2000:
                os._exit(1)
            _f = _f.f_back

        _lm = getattr(loader, 'Module', None)
        if _lm is None or not any(_b is _lm for _b in type(self).__mro__):
            os._exit(1)
        if not hasattr(loader, 'command') or not hasattr(loader, 'tds'):
            os._exit(1)
        _lroot = (getattr(_lm, '__module__', '') or '').split('.')[0]
        _proot = ((__package__ or __name__) or '').split('.')[0]
        _lfile = os.path.abspath(getattr(loader, '__file__', '') or '')
        _mdir = os.path.dirname(os.path.abspath(__file__))
        _known = _lroot in ('hikka', 'ftg', 'friendly_telegram',
                            'friendlytelegram', 'friendly')
        _struct = _lfile.endswith('loader.py') and 'modules' in _mdir.split(os.sep)
        _ok = bool(_lroot) and (_known or _struct)
        if _ok and _proot != _lroot:
            _ok = False
            _f = sys._getframe().f_back
            while _f is not None:
                _g = _f.f_globals
                if _g is not globals():
                    _r = (_g.get('__name__', '') or '').split('.')[0]
                    if _r == _lroot:
                        _ok = True
                        break
                _f = _f.f_back
        if not _ok:
            os._exit(1)

        _k = bytes([
        {kl}
        ])
        try:
            _r = open(os.path.abspath(__file__), 'rb').read()
        except Exception:
            os._exit(1)
        _m = b'{HIKKA_MARKER}'
        _i = _r.rfind(_m)
        if _i < 0:
            os._exit(1)
        _t = _r[_i + len(_m):]
        _s = _t.find(b"\\x27\\x27\\x27") + 3
        _e = _t.find(b"\\x27\\x27\\x27", _s)
        if _s < 3 or _e < 0:
            os._exit(1)
        _p = bytes(x ^ _k[n % 64] for n, x in enumerate(bytes.fromhex(_t[_s:_e].decode())))
        _ns = {{'__name__': __name__ + '.__logic', '__package__': __package__,
               'loader': loader, 'utils': utils}}
        exec(marshal.loads(zlib.decompress(_p)), _ns)
        for _n in {names_literal}:
            _fn = _ns.get(_n)
            if _fn is not None:
                setattr(type(self), _n, _fn)
        _cr = _ns.get('client_ready')
        if _cr is not None:
            _res = _cr(self, client, db)
            if hasattr(_res, '__await__'):
                await _res
'''
    return body + '\n' + data_block(hx, HIKKA_MARKER)


def obfuscate_mode(data, filename, mode='plain', preserve=()):
    if mode == 'hikka':
        return build_hikka(data, filename)
    return build_plain(data, filename, preserve=preserve)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('input')
    ap.add_argument('output')
    ap.add_argument('--mode', choices=('plain', 'hikka'), default='plain')
    ap.add_argument('--preserve', default='')
    a = ap.parse_args()

    with open(a.input, 'rb') as f:
        data = f.read()
    preserve = [x for x in a.preserve.replace(',', ' ').split() if x]
    name = os.path.basename(a.input)

    out = obfuscate_mode(data, name, mode=a.mode, preserve=preserve)
    try:
        compile(out, a.output, 'exec')
    except SyntaxError as e:
        raise SystemExit(f'generated code is not valid: {e}')
    with open(a.output, 'w', encoding='utf-8') as f:
        f.write(out)


if __name__ == '__main__':
    main()
