"""Safe control: loading a trusted model file from a fixed local path.

torch.load is a modeled deserialization SINK, but this call takes a constant,
non-attacker-controlled path -- no taint source reaches it -- so the dataflow
rule must NOT fire. This proves the new deserializer sinks stay silent on the
pervasive trusted-local model-loading pattern (the anti-flood guarantee).
"""
import torch

from flask import Flask

app = Flask(__name__)


@app.route("/model")
def load_model():
    model = torch.load("/opt/models/classifier.pt")
    return str(type(model))
