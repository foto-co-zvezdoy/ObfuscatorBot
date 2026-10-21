# -*- coding: utf-8 -*-
"""Текстовая обфускация .bat/.cmd.

Только стандартные re и random. Ничего не запускает и не компилирует:
меняет имена пользовательских переменных, убирает комментарии и добавляет
безопасные мусорные строки, сохраняя ключевые конструкции batch.
"""
import random
import re

# Переменные, которые нельзя переименовывать: их читают cmd/Windows/другие программы.
_SYSTEM_VARS = {
    "path", "pathext", "comspec", "systemroot", "windir", "systemdrive",
    "temp", "tmp", "cd", "errorlevel", "date", "time", "random",
    "cmdcmdline", "cmdextversion", "userprofile", "appdata", "localappdata",
    "programfiles", "programfiles(x86)", "programdata", "allusersprofile",
    "homedrive", "homepath", "logonserver", "username", "userdomain",
    "computername", "number_of_processors", "os", "processor_architecture",
    "processor_identifier", "processor_level", "processor_revision", "public",
    "sessionname", "prompt", "dircmd", "copycmd", "ver", "__cd__", "__appdir__",
}

# Служебные слова batch: не используем их как новые имена переменных.
_RESERVED = {
    "if", "else", "for", "do", "in", "goto", "call", "set", "echo", "rem",
    "exit", "not", "defined", "exist", "errorlevel", "cmdextversion", "equ",
    "neq", "lss", "leq", "gtr", "geq", "off", "on", "con", "prn", "aux", "nul",
    "com1", "com2", "com3", "com4", "com5", "com6", "com7", "com8", "com9",
    "lpt1", "lpt2", "lpt3", "lpt4", "lpt5", "lpt6", "lpt7", "lpt8", "lpt9",
}

# %VAR% и %VAR:~0,3% / %VAR:old=new%
_PCT_RE = re.compile(r"%([A-Za-z_][A-Za-z0-9_]*)(:[^%]*)?%")
# !VAR! и !VAR:~0,3! (delayed expansion)
_BANG_RE = re.compile(r"!([A-Za-z_][A-Za-z0-9_]*)(:[^!]*)?!")
# if defined VAR / if not defined VAR
_IF_DEFINED_RE = re.compile(
    r"(?i)(\bif\s+(?:not\s+)?defined\s+)([A-Za-z_][A-Za-z0-9_]*)"
)
_SET_A_RE = re.compile(r"(?i)\bset\s+/a\b")

# Начало команды set: начало строки, & | ( ), do/else/call,
# а также однострочный if (if exist file set VAR=1).
_SET_PREFIX = (
    r"(?:^|[&(|)]|\b(?:do|else|call)\b|\bif\b[^&|()\r\n]*?)"
    r"\s*@?\s*set\s+(?:/(?:a|p)\s+)?"
)
_DEF_RENAME_RE = re.compile(
    r"(?i)(?P<pre>" + _SET_PREFIX + r")(?P<q>\"?)(?P<name>[A-Za-z_][A-Za-z0-9_]*)"
    r"(?=\s*(?:<<=|>>=|(?:\+|-|\*|/|%|&|\||\^)?=(?!=)))"
)
# Дополнительные присваивания внутри set /a a=1,b=2
_SET_A_EXTRA_RE = re.compile(
    r"(?:^|,)\s*([A-Za-z_][A-Za-z0-9_]*)\s*"
    r"(?:<<=|>>=|(?:\+|-|\*|/|%|&|\||\^)?=(?!=))"
)


def _split_eol(line):
    if line.endswith("\r\n"):
        return line[:-2], "\r\n"
    if line.endswith("\n"):
        return line[:-1], "\n"
    if line.endswith("\r"):
        return line[:-1], "\r"
    return line, ""


def _is_comment(body):
    """Строка целиком является комментарием rem/@rem/:: ?"""
    s = body.lstrip(" \t")
    if s.startswith("@"):
        s = s[1:].lstrip(" \t")
    if s.startswith("::"):
        return True
    low = s.lower()
    if low == "rem":
        return True
    # rem, rem., rem=... — комментарий; remove — уже нет.
    return low.startswith("rem") and len(low) > 3 and not low[3].isalnum()


def _paren_delta(body):
    """Приблизительный счётчик открытых/закрытых скобок вне кавычек."""
    depth = 0
    in_quote = False
    i = 0
    while i < len(body):
        ch = body[i]
        if ch == '"':
            in_quote = not in_quote
        elif not in_quote:
            if ch == "^":
                i += 1  # экранированный символ
            elif ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
        i += 1
    return depth


def _used_names(body):
    names = set()
    for m in _PCT_RE.finditer(body):
        names.add(m.group(1).lower())
    for m in _BANG_RE.finditer(body):
        names.add(m.group(1).lower())
    for m in _IF_DEFINED_RE.finditer(body):
        names.add(m.group(2).lower())
    for m in re.finditer(r"%%([A-Za-z])", body):
        names.add(m.group(1).lower())

    m = _SET_A_RE.search(body)
    if m:
        for mm in re.finditer(r"\b[A-Za-z_][A-Za-z0-9_]*\b", body[m.end():]):
            names.add(mm.group(0).lower())
    return names


def _collect_defined(lines):
    names = set()
    for body in lines:
        for m in _DEF_RENAME_RE.finditer(body):
            names.add(m.group("name"))
            if re.search(r"(?i)/a\b", m.group("pre")):
                for am in _SET_A_EXTRA_RE.finditer(body[m.end():]):
                    names.add(am.group(1))
    return names


def _gen_name(used):
    """a1, b2, q4821... — гарантированно новое имя."""
    letters = "abcdefghijklmnopqrstuvwxyz"
    while True:
        name = random.choice(letters) + str(random.randint(1, 99999))
        low = name.lower()
        if low not in used and low not in _SYSTEM_VARS and low not in _RESERVED:
            used.add(low)
            return name


def _build_mapping(lines):
    defined = _collect_defined(lines)
    used = {n.lower() for n in defined}
    for body in lines:
        used.update(_used_names(body))

    uniq = {}
    for name in defined:
        uniq.setdefault(name.lower(), name)

    mapping = {}
    for low in sorted(uniq):
        if low in _SYSTEM_VARS or low in _RESERVED:
            continue
        mapping[low] = _gen_name(used)
    return mapping, used


def _rewrite_line(body, mapping):
    if not mapping:
        return body

    def def_repl(m):
        new = mapping.get(m.group("name").lower())
        if not new:
            return m.group(0)
        return m.group("pre") + m.group("q") + new

    body = _DEF_RENAME_RE.sub(def_repl, body)

    def use_repl(m, sigil):
        new = mapping.get(m.group(1).lower())
        if not new:
            return m.group(0)
        return sigil + new + (m.group(2) or "") + sigil

    body = _PCT_RE.sub(lambda m: use_repl(m, "%"), body)
    body = _BANG_RE.sub(lambda m: use_repl(m, "!"), body)

    def if_repl(m):
        new = mapping.get(m.group(2).lower())
        return m.group(1) + (new if new else m.group(2))

    body = _IF_DEFINED_RE.sub(if_repl, body)

    # set /a: имена справа от set /a используются без %.
    m = _SET_A_RE.search(body)
    if m:
        head, tail = body[:m.end()], body[m.end():]

        def bare_repl(mm):
            new = mapping.get(mm.group(0).lower())
            return new if new else mm.group(0)

        tail = re.sub(r"\b[A-Za-z_][A-Za-z0-9_]*\b", bare_repl, tail)
        body = head + tail

    return body


def obfuscate_batch(content: str) -> str:
    """Обфусцирует текст .bat/.cmd, не ломая синтаксис.

    - сохраняет @echo off, setlocal, chcp, :labels, goto, if, for;
    - консистентно переименовывает только пользовательские set-переменные;
    - удаляет rem/:: комментарии (внутри блоков ставит безопасный no-op);
    - добавляет мусорные строки в начало.
    """
    if content is None:
        return ""

    if "\r\n" in content:
        eol = "\r\n"
    elif "\n" in content:
        eol = "\n"
    elif "\r" in content:
        eol = "\r"
    else:
        eol = "\r\n"

    kept = []
    depth = 0
    for line in content.splitlines(keepends=True):
        body, end = _split_eol(line)
        if _is_comment(body):
            # Пустой блок if (...) / for (...) do (...) в cmd ломается,
            # поэтому внутри скобок оставляем безвредный no-op.
            if depth > 0:
                kept.append(("@echo.>nul", end))
            continue
        kept.append((body, end))
        depth = max(0, depth + _paren_delta(body))

    bodies = [b for b, _ in kept]
    mapping, used = _build_mapping(bodies)

    out = []
    for body, end in kept:
        out.append(_rewrite_line(body, mapping) + end)

    j1 = _gen_name(used)
    j2 = _gen_name(used)
    junk = (
        f"@set /a {j1}=1+1{eol}"
        f"@echo.>nul{eol}"
        f"@set /a {j2}=2*2{eol}"
    )
    return junk + "".join(out)
