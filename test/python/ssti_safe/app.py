"""FP guard for py-ssti: passing the untrusted value as template CONTEXT (a keyword
argument) is the intended, safe path — the template source (#0) is a fixed literal,
so the auto-escaped `{{ name }}` renders it as data. Must produce ZERO findings.
"""
from flask import Flask, request, render_template_string

app = Flask(__name__)


@app.route("/greet")
def greet():
    name = request.args.get("name")
    return render_template_string("<h1>Hello {{ name }}</h1>", name=name)  # safe: user data is context
