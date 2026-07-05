"""Safe counterpart: the untrusted value is parsed with ast.literal_eval, which
only evaluates Python LITERALS (never code), so it must NOT be flagged. Guards
the exact-name sink match (eval/exec/compile) against the literal_eval false
positive. Expect zero findings.
"""
import ast
from flask import Flask, request

app = Flask(__name__)


@app.route("/parse")
def parse():
    data = request.args.get("data")
    value = ast.literal_eval(data)  # safe: literals only, not a code-injection sink
    return str(value)
