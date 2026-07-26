"""FP sentinel: the same APIs with their flags set safely, plus unrelated
keywords that happen to be boolean. A config rule matches on the keyword's NAME
and VALUE together, so none of these may fire -- in particular `check=True` must
not be mistaken for a dangerous flag just because it is a true boolean.
"""
import subprocess

import requests
from flask import Flask
from jinja2 import Environment
from langchain_experimental.agents import create_csv_agent

app = Flask(__name__)


def fetch(url):
    return requests.get(url, timeout=5, verify=True)


def render(tmpl):
    return Environment(autoescape=True).from_string(tmpl)


def agent(path):
    return create_csv_agent(None, path, allow_dangerous_code=False)


def serve():
    app.run(host="127.0.0.1", debug=False)


def run_checked(args):
    # An unrelated true boolean keyword: not a security flag.
    return subprocess.run(args, check=True, capture_output=True)
