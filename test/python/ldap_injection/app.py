"""LDAP injection (CWE-90): an untrusted request value is concatenated into an
LDAP search filter, so an attacker can alter the query (auth bypass / disclosure).
"""
import ldap
from flask import Flask, request

app = Flask(__name__)


@app.route("/login")
def login():
    user = request.args.get("user")
    conn = ldap.initialize("ldap://localhost")
    return conn.search_s("dc=example,dc=com", ldap.SCOPE_SUBTREE, "(uid=" + user + ")")  # LDAP injection
