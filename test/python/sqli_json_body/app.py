"""SQL injection sourced from a JSON request body (request.get_json()), the
dominant shape for JSON APIs. Taint flows from the parsed body, through the
subscript access, into an unparameterized query.
"""
from flask import Flask, request

app = Flask(__name__)
_cursor = None


@app.route("/u", methods=["POST"])
def u():
    data = request.get_json()                                 # untrusted JSON body (source)
    uid = data["id"]                                          # subscript -> taint propagates
    _cursor.execute("SELECT * FROM users WHERE id = " + uid)  # sink
    return "ok"
