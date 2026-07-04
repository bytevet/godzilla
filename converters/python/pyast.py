#!/usr/bin/env python3
"""pyast.py - Parse a Python source file with the stdlib `ast` module and emit
a compact JSON tree on stdout.

This script is embedded into the Go binary via //go:embed and executed as
`python3 pyast.py <file.py>` by converters/python/converter.go, which builds
gIR from the JSON it prints. It has no dependencies beyond the Python 3
standard library (ast, json, sys) so it works with any python3 on PATH.

Output shape
------------
On success, prints a single JSON object to stdout:

    {"kind": "Module", "body": [<stmt>, ...]}

On a parse error, prints {"error": "<message>"} to stdout and exits 1.

Every statement/expression node is a JSON object with a "kind" field and a
"pos": {"line": <1-based>, "col": <1-based>} field (Python's col_offset is
0-based; 1 is added here so callers can treat every language uniformly).

Statement kinds
---------------
  FunctionDef   {name, params: [str, ...], body: [stmt, ...]}
  ClassDef      {name, body: [stmt, ...]}
  Assign        {targets: [expr, ...], value: expr}
  AugAssign     {target: expr, op: BinOpStr, value: expr}
  ExprStmt      {value: expr}
  Return        {value: expr | null}
  If            {body: [stmt, ...], orelse: [stmt, ...]}      (test omitted)
  For / While   {body: [stmt, ...], orelse: [stmt, ...]}      (test omitted)
  With          {body: [stmt, ...]}
  Try           {body, handlers: [{body}], orelse, finalbody}
  Pass / Import / ImportFrom / Global / Nonlocal / Break / Continue /
  Raise / Assert / Delete   {}   (no-ops; dropped by the converter)
  Unknown       {note: "<ast class name>"}   (anything else)

Expression kinds
-----------------
  Constant        {value_type: "bool"|"int"|"float"|"str"|"none"|"other",
                    value: <json-native or string>}
  Name            {id: str}
  Attribute       {value: expr, attr: str}
  Subscript       {value: expr, slice: expr | null}  (null for a[i:j] slices)
  Call            {func: expr, args: [expr, ...],
                    keywords: [{arg: str|null, value: expr}, ...]}
  BinOp           {op: "ADD"|"SUB"|"MUL"|"QUO"|"REM"|"AND"|"OR"|"XOR"|
                        "SHL"|"SHR", left: expr, right: expr}
  UnaryOp         {op: "NOT"|"NEG"|"POS"|"BIT_NOT", operand: expr}
  JoinedStr       {values: [expr, ...]}     (f-string parts)
  FormattedValue  {value: expr}             (an f-string {expr} slot)
  Unknown         {note: "<ast class name>"} (BoolOp, Compare, List, Tuple,
                    Dict, Set, Lambda, comprehensions, Starred, etc.)
"""
import ast
import json
import sys

BIN_OP_MAP = {
    ast.Add: "ADD",
    ast.Sub: "SUB",
    ast.Mult: "MUL",
    ast.Div: "QUO",
    ast.FloorDiv: "QUO",
    ast.Mod: "REM",
    ast.LShift: "SHL",
    ast.RShift: "SHR",
    ast.BitAnd: "AND",
    ast.BitOr: "OR",
    ast.BitXor: "XOR",
}

UNARY_OP_MAP = {
    ast.Not: "NOT",
    ast.USub: "NEG",
    ast.UAdd: "POS",
    ast.Invert: "BIT_NOT",
}


def pos(node):
    return {
        "line": getattr(node, "lineno", 0) or 0,
        "col": (getattr(node, "col_offset", 0) or 0) + 1,
    }


def arg_names(args: ast.arguments):
    names = []
    for a in getattr(args, "posonlyargs", []):
        names.append(a.arg)
    for a in args.args:
        names.append(a.arg)
    if args.vararg:
        names.append(args.vararg.arg)
    for a in args.kwonlyargs:
        names.append(a.arg)
    if args.kwarg:
        names.append(args.kwarg.arg)
    return names


def conv_body(stmts):
    return [conv_stmt(s) for s in stmts]


def conv_comprehension(g):
    # One `for target in iter if cond ...` clause of a comprehension.
    return {
        "target": conv_expr(g.target),
        "iter": conv_expr(g.iter),
        "ifs": [conv_expr(i) for i in g.ifs],
    }


def conv_stmt(node):
    p = pos(node)

    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return {
            "kind": "FunctionDef",
            "name": node.name,
            "params": arg_names(node.args),
            "body": conv_body(node.body),
            "pos": p,
        }
    if isinstance(node, ast.ClassDef):
        return {"kind": "ClassDef", "name": node.name, "body": conv_body(node.body), "pos": p}
    if isinstance(node, ast.Assign):
        return {
            "kind": "Assign",
            "targets": [conv_expr(t) for t in node.targets],
            "value": conv_expr(node.value),
            "pos": p,
        }
    if isinstance(node, ast.AugAssign):
        return {
            "kind": "AugAssign",
            "target": conv_expr(node.target),
            "op": BIN_OP_MAP.get(type(node.op), "UNSPECIFIED"),
            "value": conv_expr(node.value),
            "pos": p,
        }
    if isinstance(node, ast.Expr):
        return {"kind": "ExprStmt", "value": conv_expr(node.value), "pos": p}
    if isinstance(node, ast.Return):
        return {"kind": "Return", "value": conv_expr(node.value) if node.value else None, "pos": p}
    if isinstance(node, ast.If):
        return {
            "kind": "If",
            "test": conv_expr(node.test),
            "body": conv_body(node.body),
            "orelse": conv_body(node.orelse),
            "pos": p,
        }
    if isinstance(node, (ast.For, ast.AsyncFor)):
        return {
            "kind": "For",
            "target": conv_expr(node.target),
            "iter": conv_expr(node.iter),
            "body": conv_body(node.body),
            "orelse": conv_body(node.orelse),
            "pos": p,
        }
    if isinstance(node, ast.While):
        return {
            "kind": "While",
            "test": conv_expr(node.test),
            "body": conv_body(node.body),
            "orelse": conv_body(node.orelse),
            "pos": p,
        }
    if isinstance(node, (ast.With, ast.AsyncWith)):
        return {"kind": "With", "body": conv_body(node.body), "pos": p}
    if isinstance(node, ast.Try):
        return {
            "kind": "Try",
            "body": conv_body(node.body),
            "handlers": [{"body": conv_body(h.body)} for h in node.handlers],
            "orelse": conv_body(node.orelse),
            "finalbody": conv_body(node.finalbody),
            "pos": p,
        }
    # Imports carry their names+asnames so the lowering can resolve aliased and
    # from-imported sink modules (FE-2): `import subprocess as sp` / `from os
    # import system` otherwise silently break module-anchored sink matching.
    if isinstance(node, ast.Import):
        return {
            "kind": "Import",
            "names": [{"name": a.name, "asname": a.asname} for a in node.names],
            "pos": p,
        }
    if isinstance(node, ast.ImportFrom):
        return {
            "kind": "ImportFrom",
            "module": node.module,
            "level": node.level,
            "names": [{"name": a.name, "asname": a.asname} for a in node.names],
            "pos": p,
        }
    if isinstance(
        node,
        (
            ast.Pass,
            ast.Global,
            ast.Nonlocal,
            ast.Break,
            ast.Continue,
            ast.Raise,
            ast.Assert,
            ast.Delete,
        ),
    ):
        return {"kind": type(node).__name__, "pos": p}

    return {"kind": "Unknown", "note": type(node).__name__, "pos": p}


def conv_expr(node):
    if node is None:
        return None
    p = pos(node)

    if isinstance(node, ast.Constant):
        v = node.value
        if isinstance(v, bool):
            return {"kind": "Constant", "value_type": "bool", "value": v, "pos": p}
        if isinstance(v, int):
            return {"kind": "Constant", "value_type": "int", "value": v, "pos": p}
        if isinstance(v, float):
            return {"kind": "Constant", "value_type": "float", "value": v, "pos": p}
        if isinstance(v, str):
            return {"kind": "Constant", "value_type": "str", "value": v, "pos": p}
        if v is None:
            return {"kind": "Constant", "value_type": "none", "value": None, "pos": p}
        return {"kind": "Constant", "value_type": "other", "value": repr(v), "pos": p}

    if isinstance(node, ast.Name):
        return {"kind": "Name", "id": node.id, "pos": p}

    if isinstance(node, ast.Attribute):
        return {"kind": "Attribute", "value": conv_expr(node.value), "attr": node.attr, "pos": p}

    if isinstance(node, ast.Subscript):
        sl = node.slice
        # Python <3.9 wraps a plain index in ast.Index; 3.9+ uses the expr
        # directly. A real ast.Slice (a[i:j]) has no single expression value.
        if hasattr(ast, "Index") and isinstance(sl, ast.Index):
            sl = sl.value
        if isinstance(sl, ast.Slice):
            sl_json = None
        else:
            sl_json = conv_expr(sl)
        return {"kind": "Subscript", "value": conv_expr(node.value), "slice": sl_json, "pos": p}

    if isinstance(node, ast.Call):
        return {
            "kind": "Call",
            "func": conv_expr(node.func),
            "args": [conv_expr(a) for a in node.args],
            "keywords": [{"arg": kw.arg, "value": conv_expr(kw.value)} for kw in node.keywords],
            "pos": p,
        }

    if isinstance(node, ast.BinOp):
        return {
            "kind": "BinOp",
            "op": BIN_OP_MAP.get(type(node.op), "UNSPECIFIED"),
            "left": conv_expr(node.left),
            "right": conv_expr(node.right),
            "pos": p,
        }

    if isinstance(node, ast.UnaryOp):
        return {
            "kind": "UnaryOp",
            "op": UNARY_OP_MAP.get(type(node.op), "UNSPECIFIED"),
            "operand": conv_expr(node.operand),
            "pos": p,
        }

    if isinstance(node, ast.BoolOp):
        # `a or b` / `a and b`: the result is one of the operands, so taint from
        # any operand can reach it. Emit all operands for the lowerer to model
        # as a taint-merging BIN_OP.
        return {"kind": "BoolOp", "values": [conv_expr(v) for v in node.values], "pos": p}

    if isinstance(node, ast.IfExp):
        # ternary `a if cond else b`: the result is a or b, so taint from either
        # branch can reach it. `test` is emitted for its side effects only.
        return {
            "kind": "IfExp",
            "test": conv_expr(node.test),
            "body": conv_expr(node.body),
            "orelse": conv_expr(node.orelse),
            "pos": p,
        }

    if isinstance(node, ast.NamedExpr):
        # walrus `target := value`: the expression's value is `value`, and it
        # also binds `target`.
        return {"kind": "NamedExpr", "target": conv_expr(node.target), "value": conv_expr(node.value), "pos": p}

    if isinstance(node, (ast.ListComp, ast.SetComp, ast.GeneratorExp)):
        # [elt for t in iter if cond ...]: emit the element and each generator so
        # a source/sink inside the comprehension is lowered and the loop target
        # can inherit the iterable's taint.
        return {"kind": "Comprehension", "elt": conv_expr(node.elt),
                "generators": [conv_comprehension(g) for g in node.generators], "pos": p}

    if isinstance(node, ast.DictComp):
        return {"kind": "Comprehension", "key": conv_expr(node.key), "value": conv_expr(node.value),
                "generators": [conv_comprehension(g) for g in node.generators], "pos": p}

    if isinstance(node, ast.JoinedStr):
        return {"kind": "JoinedStr", "values": [conv_expr(v) for v in node.values], "pos": p}

    if isinstance(node, ast.FormattedValue):
        return {"kind": "FormattedValue", "value": conv_expr(node.value), "pos": p}

    if isinstance(node, ast.Await):
        # `await x` yields x's resolved value; for taint it is transparent.
        return {"kind": "Await", "value": conv_expr(node.value), "pos": p}

    if isinstance(node, (ast.List, ast.Tuple)):
        # As a VALUE: a list/tuple literal (lower elements so an inner source/sink
        # fires; the container itself stays untainted). As an unpacking TARGET
        # (a, b = ...): bind each element. Both are handled by the "Sequence"
        # lowering, distinguished by context (lowerExpr vs assign).
        return {"kind": "Sequence", "elts": [conv_expr(e) for e in node.elts], "pos": p}

    if isinstance(node, ast.Starred):
        return {"kind": "Starred", "value": conv_expr(node.value), "pos": p}

    return {"kind": "Unknown", "note": type(node).__name__, "pos": p}


def main():
    if len(sys.argv) != 2:
        print(json.dumps({"error": "usage: pyast.py <file.py>"}))
        sys.exit(1)

    path = sys.argv[1]
    try:
        with open(path, "r", encoding="utf-8") as f:
            source = f.read()
        tree = ast.parse(source, filename=path)
    except SyntaxError as e:
        print(json.dumps({"error": f"syntax error: {e}"}))
        sys.exit(1)
    except OSError as e:
        print(json.dumps({"error": f"read error: {e}"}))
        sys.exit(1)

    out = {"kind": "Module", "body": conv_body(tree.body)}
    print(json.dumps(out))


if __name__ == "__main__":
    main()
