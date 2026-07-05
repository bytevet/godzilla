"""Flask handler with a code injection (CWE-95).

GET /calc?expr=<expr> reads an untrusted query parameter and passes it to eval,
which executes it as Python code — arbitrary remote code execution.
"""
from flask import Flask, request

app = Flask(__name__)


@app.route("/calc")
def calc():
    expr = request.args.get("expr")
    result = eval(expr)  # code injection sink
    return str(result)
