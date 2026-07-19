"""XPath injection (CWE-643): an untrusted request value is concatenated into an
lxml XPath expression, so an attacker can alter the query (auth bypass / disclosure).
"""
from lxml import etree
from flask import Flask, request

app = Flask(__name__)


@app.route("/find")
def find():
    name = request.args.get("name")
    tree = etree.parse("data.xml")
    return tree.xpath("//user[@name='" + name + "']")  # XPath injection
