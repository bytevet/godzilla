"""Safe control for py-dynamic-code-exec: nothing dynamic is executed.

The guard on that rule is `!arg[0].Complete`, so a fully constant literal must
stay silent, and ast.literal_eval — which parses a literal without executing
code — must stay silent even on a non-constant argument, because the rule names
eval/exec exactly rather than by wildcard. Both are asserted here (expected
findings are empty).
"""
import ast


def defaults():
    # Fully constant argument: real (if pointless) eval, but nothing an
    # attacker can influence, so the rule must not fire.
    return eval("{'retries': 3, 'timeout': 30}")


def parse_row(row):
    # The safe literal parser, on a value that is NOT constant: still silent.
    return ast.literal_eval(row)
