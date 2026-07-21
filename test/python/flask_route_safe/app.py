"""Safe control for the Flask ``@app.route`` path-param source.

The route capture ``name`` is untrusted and IS seeded as a source, but it
never reaches a dangerous sink -- it is only echoed back in a response
string. Seeding a request source must not, on its own, produce a finding;
this sample asserts that adding ``route`` to the recognized route decorators
does not create a false positive.
"""
from flask import Flask

app = Flask(__name__)


@app.route("/hello/<name>")
def hello(name):
    return "hello " + name  # not a sink; no finding expected
