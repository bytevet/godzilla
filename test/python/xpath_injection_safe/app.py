"""FP guard for py-xpath-injection: the untrusted value is bound as an XPath
variable (parameterized query), so it never becomes part of the expression string.
The expression argument (#0) is a fixed literal. Must produce ZERO findings.
"""
from lxml import etree
from flask import Flask, request

app = Flask(__name__)


@app.route("/find")
def find():
    name = request.args.get("name")
    tree = etree.parse("data.xml")
    return tree.xpath("//user[@name=$n]", n=name)  # parameterized -> safe
