"""Flask handler with a classic reflected XSS vulnerability.

GET /greet?name=<name> reads an untrusted query parameter and splices it
directly into the *template source string* passed to
render_template_string(), without escaping, so an attacker-controlled `name`
can inject arbitrary HTML/script that executes in the victim's browser.
"""
from flask import Flask, request, render_template_string

app = Flask(__name__)


@app.route("/greet")
def greet():
    name = request.args.get("name")
    return render_template_string("<h1>Hello " + name + "</h1>")
