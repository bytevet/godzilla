"""Server-side template injection (CWE-1336): an untrusted request value is used
as the Jinja2 TEMPLATE STRING, which Flask compiles and renders server-side — a
path to RCE via `{{ ().__class__... }}`.
"""
from flask import Flask, request, render_template_string

app = Flask(__name__)


@app.route("/greet")
def greet():
    name = request.args.get("name")
    return render_template_string("<h1>Hello " + name + "</h1>")  # SSTI sink (#0)
