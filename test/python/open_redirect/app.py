from flask import Flask, request, redirect

app = Flask(__name__)


@app.route("/go")
def open_redirect():
    target = request.args.get("url")  # untrusted input
    return redirect(target)           # open redirect
