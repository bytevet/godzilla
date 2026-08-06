#!/usr/bin/env python3
"""pyast.py - Parse a Python source file with the stdlib `ast` module and emit
a compact JSON tree on stdout.

Embedded into the Go binary via //go:embed and executed as
`python3 pyast.py [--batch] <file.py> [more...]` by
converters/python/converter.go, which builds gIR from the JSON it prints. It
has no dependencies beyond the Python 3 standard library, so it works with any
python3 on PATH.

Output shape
------------
Each file's document is a single JSON object:

    {"kind": "Module", "body": [<stmt>, ...]}

or, when that file failed to parse/read, {"error": "<message>"}.

Batch mode (--batch): one JSON document per line, in argv order, always exit
0 — a per-file failure is that file's own {"error": ...} line, so one broken
file cannot hide the rest, and interpreter startup is paid once per batch. The
Go frontend ALWAYS passes --batch, including for a single-file scan. Single-file
mode exists only for running this script by hand: the bare document on stdout,
exit 1 on failure.

Every statement/expression node is a JSON object with a "kind" field and a
"pos": {"line": <1-based>, "col": <1-based>} field (Python's col_offset is
0-based; 1 is added here so callers can treat every language uniformly).

Statement kinds
---------------
  FunctionDef   {name, params: [str, ...], decorators: [str, ...],
                  depends_params: [str, ...], body: [stmt, ...]}
                  (decorators are dotted names, e.g. ["app.get"]; depends_params
                   are params defaulted to a FastAPI Depends()/Security() call)
  ClassDef      {name, bases: [str, ...], body: [stmt, ...]}
                  (bases are dotted names, e.g. ["tornado.web.RequestHandler"])
  Assign        {targets: [expr, ...], value: expr}
  AugAssign     {target: expr, op: BinOpStr, value: expr}
  ExprStmt      {value: expr}
  Return        {value: expr | null}
  If            {test: expr, body: [stmt, ...], orelse: [stmt, ...]}
  For           {target: expr, iter: expr, body: [stmt, ...], orelse: [stmt, ...]}
  While         {test: expr, body: [stmt, ...], orelse: [stmt, ...]}
  With          {items: [{context: expr, vars: expr | null}, ...],
                  body: [stmt, ...]}
  Try           {body, handlers: [{body}], orelse, finalbody}
                  (a handler carries only its body — no exception type/name)
  Import        {names: [{name: str, asname: str | null}, ...]}
  ImportFrom    {module: str | null, level: int,
                  names: [{name: str, asname: str | null}, ...]}
                  (both are lowered as no-op statements, but their names drive
                   the frontend's import-alias resolution)
  Pass / Global / Nonlocal / Break / Continue /
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
  BoolOp          {values: [expr, ...]}     (a or b / a and b)
  Compare         {left: expr, comparators: [expr, ...]}  (ops omitted)
  IfExp           {test: expr, body: expr, orelse: expr}  (ternary)
  NamedExpr       {target: expr, value: expr}             (walrus :=)
  Comprehension   {elt: expr, generators: [{target, iter, ifs: [expr, ...]}, ...]}
                    (a DictComp emits {key, value} instead of {elt})
  Await           {value: expr}
  Sequence        {elts: [expr, ...]}
                    (List/Tuple/Set literals, a flattened Dict literal, and —
                     as an assignment TARGET — tuple/list unpacking)
  Starred         {value: expr}             (*rest)
  Unknown         {note: "<ast class name>"} (Lambda and anything else)
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


def dotted_of(node):
    """Best-effort dotted name for a decorator / class-base expression.

    Name("app") -> "app"; Attribute(Name("app"),"get") -> "app.get";
    Call(func=...) -> dotted name of the callee (so @APIRouter().get(...) ->
    "APIRouter.get"). Anything else -> "".
    """
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = dotted_of(node.value)
        return (base + "." + node.attr) if base else node.attr
    if isinstance(node, ast.Call):
        return dotted_of(node.func)
    return ""


def decorator_names(node):
    """The dotted names of a def's decorators, e.g. ["app.get"] for @app.get(...)."""
    return [d for d in (dotted_of(d) for d in node.decorator_list) if d]


def depends_params(args: ast.arguments):
    """Names of parameters whose default is a FastAPI Depends(...)/Security(...)
    call — these are dependency-injected, not raw request input, so callers
    must NOT treat them as taint sources."""

    def is_depends(default):
        if isinstance(default, ast.Call):
            last = dotted_of(default.func).rsplit(".", 1)[-1]
            return last in ("Depends", "Security")
        return False

    out = []
    positional = list(getattr(args, "posonlyargs", [])) + list(args.args)
    defaults = list(args.defaults)
    if defaults:
        for a, d in zip(positional[len(positional) - len(defaults):], defaults):
            if is_depends(d):
                out.append(a.arg)
    for a, d in zip(args.kwonlyargs, args.kw_defaults):
        if d is not None and is_depends(d):
            out.append(a.arg)
    return out


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
            "decorators": decorator_names(node),
            "depends_params": depends_params(node.args),
            "body": conv_body(node.body),
            "pos": p,
        }
    if isinstance(node, ast.ClassDef):
        return {
            "kind": "ClassDef",
            "name": node.name,
            "bases": [b for b in (dotted_of(b) for b in node.bases) if b],
            "body": conv_body(node.body),
            "pos": p,
        }
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
        # The context-manager items are emitted so the frontend can lower them as
        # `VAR = EXPR`; see lowerBody's "With" case.
        items = [
            {
                "context": conv_expr(it.context_expr),
                "vars": conv_expr(it.optional_vars) if it.optional_vars is not None else None,
            }
            for it in node.items
        ]
        return {"kind": "With", "items": items, "body": conv_body(node.body), "pos": p}
    if isinstance(node, ast.Try):
        return {
            "kind": "Try",
            "body": conv_body(node.body),
            # `except E as name` is not lowered as a statement, but it DOES bind
            # a name, which constglobal.go's whole-module walk must be able to see.
            "handlers": [{"name": h.name, "body": conv_body(h.body)} for h in node.handlers],
            "orelse": conv_body(node.orelse),
            "finalbody": conv_body(node.finalbody),
            "pos": p,
        }
    # Imports carry their names+asnames so the lowering can resolve aliased and
    # from-imported sink modules; without them `import subprocess as sp` silently
    # breaks module-anchored sink matching.
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
    if isinstance(node, ast.AnnAssign):
        # `x: T = v` binds exactly like `x = v` -- the annotation is irrelevant to
        # dataflow. Emitting it as Unknown instead would drop the VALUE too, so
        # `x: str = tainted()` would lose its taint entirely. Without a value it
        # declares only a type and binds nothing, so it is inert.
        if node.value is None:
            return {"kind": "Pass", "pos": p}
        return {
            "kind": "Assign",
            "targets": [conv_expr(node.target)],
            "value": conv_expr(node.value),
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
        return {"kind": "BoolOp", "values": [conv_expr(v) for v in node.values], "pos": p}

    if isinstance(node, ast.Compare):
        # The comparison ops are irrelevant to taint and omitted; the operands are
        # kept so a source/sink/validator call inside the comparison still fires.
        return {"kind": "Compare", "left": conv_expr(node.left),
                "comparators": [conv_expr(c) for c in node.comparators], "pos": p}

    if isinstance(node, ast.IfExp):
        return {
            "kind": "IfExp",
            "test": conv_expr(node.test),
            "body": conv_expr(node.body),
            "orelse": conv_expr(node.orelse),
            "pos": p,
        }

    if isinstance(node, ast.NamedExpr):
        return {"kind": "NamedExpr", "target": conv_expr(node.target), "value": conv_expr(node.value), "pos": p}

    if isinstance(node, (ast.ListComp, ast.SetComp, ast.GeneratorExp)):
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
        return {"kind": "Await", "value": conv_expr(node.value), "pos": p}

    if isinstance(node, (ast.List, ast.Tuple)):
        # One "Sequence" kind serves both roles — a literal VALUE and an unpacking
        # TARGET — which the lowering distinguishes by context (lowerExpr/assign).
        return {"kind": "Sequence", "container": "list", "elts": [conv_expr(e) for e in node.elts], "pos": p}

    if isinstance(node, ast.Set):
        return {"kind": "Sequence", "container": "list", "elts": [conv_expr(e) for e in node.elts], "pos": p}

    if isinstance(node, ast.Dict):
        # Keys and values go out as one flat Sequence so a source or sink INSIDE
        # the literal — the payload shape for JSON bodies, kwargs and DB param
        # maps — is emitted and can fire. (A None key is `**spread` per PEP 448;
        # only its value is lowered.)
        #
        # container="dict" promises the elts run is key,value,key,value, so a
        # guard can address entries by key. A `**spread` contributes a value with
        # no key and breaks that alignment, so such a literal is marked "list":
        # the elements still carry taint, but no key structure is claimed.
        elts = []
        for k, v in zip(node.keys, node.values):
            if k is not None:
                elts.append(conv_expr(k))
            elts.append(conv_expr(v))
        return {
            "kind": "Sequence",
            "container": "list" if None in node.keys else "dict",
            "elts": elts,
            "pos": p,
        }

    if isinstance(node, ast.Starred):
        return {"kind": "Starred", "value": conv_expr(node.value), "pos": p}

    return {"kind": "Unknown", "note": type(node).__name__, "pos": p}


def parse_one(path):
    """Parse one file to its module JSON, or an {"error": ...} object."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            source = f.read()
        tree = ast.parse(source, filename=path)
    except SyntaxError as e:
        return {"error": f"syntax error: {e}"}
    except OSError as e:
        return {"error": f"read error: {e}"}
    return {"kind": "Module", "body": conv_body(tree.body)}


def main():
    if len(sys.argv) >= 2 and sys.argv[1] == "--batch":
        for path in sys.argv[2:]:
            print(json.dumps(parse_one(path)))
        return

    if len(sys.argv) != 2:
        print(json.dumps({"error": "usage: pyast.py [--batch] <file.py> [more files...]"}))
        sys.exit(1)

    # Single-file mode exits 1 on failure, so running this by hand fails loudly.
    out = parse_one(sys.argv[1])
    print(json.dumps(out))
    sys.exit(1 if "error" in out else 0)


if __name__ == "__main__":
    main()
