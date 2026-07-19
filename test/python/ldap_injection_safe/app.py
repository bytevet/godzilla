"""FP guard for py-ldap-injection: the untrusted value is escaped with
ldap.filter.escape_filter_chars before being placed in the filter, so the query
cannot be altered. Must produce ZERO findings.
"""
import ldap
import ldap.filter
from flask import Flask, request

app = Flask(__name__)


@app.route("/login")
def login():
    user = request.args.get("user")
    safe_user = ldap.filter.escape_filter_chars(user)   # sanitizer
    conn = ldap.initialize("ldap://localhost")
    return conn.search_s("dc=example,dc=com", ldap.SCOPE_SUBTREE, "(uid=" + safe_user + ")")
