"""Flask handler that HTML-escapes untrusted input before templating it.

GET /greet?name=<name> reads an untrusted query parameter, but passes it
through markupsafe.escape() before splicing it into the template source
string, so the resulting HTML entities can never break out into executable
markup. This must produce ZERO findings.
"""
from flask import Flask, request, render_template_string
from markupsafe import escape

app = Flask(__name__)


@app.route("/greet")
def greet():
    name = request.args.get("name")
    return render_template_string("<h1>Hello " + escape(name) + "</h1>")
