"""Security-configuration defects: safe-by-default APIs made dangerous by a flag.

None of these involve untrusted input reaching a sink -- the explicit keyword
argument IS the defect, which is why they are call-site rules gated on the
keyword's name and value rather than taint rules.
"""
import requests
from flask import Flask
from jinja2 import Environment
from langchain_experimental.agents import create_csv_agent

app = Flask(__name__)


def fetch(url):
    # TLS verification off: any certificate is accepted (machine-in-the-middle).
    return requests.get(url, timeout=5, verify=False)


def render(tmpl):
    # Autoescaping off: every rendered variable is raw HTML (XSS).
    return Environment(autoescape=False).from_string(tmpl)


def agent(path):
    # Lets the LLM execute generated Python on the host (RCE by design).
    return create_csv_agent(None, path, allow_dangerous_code=True)


def serve():
    # Exposes the Werkzeug interactive debugger: an in-browser Python console.
    app.run(host="0.0.0.0", debug=True)
