"""Flask handler with a classic command injection, used alongside broken.py
(an unparseable sibling file in this same directory) to prove that a single
bad .py file does not prevent this valid, vulnerable file from still being
converted and analyzed. See converters/python/converter_test.go's
TestConvertFile_DirectorySkipsUnparseableFile.
"""
from flask import Flask, request
import os

app = Flask(__name__)


@app.route("/ping")
def resilience_ping():
    cmd = request.args.get("cmd")
    os.system("ping " + cmd)
    return "ok"
