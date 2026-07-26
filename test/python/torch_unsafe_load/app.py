"""torch.load with weights_only=False unpickles arbitrary objects.

The flag itself is the defect: no untrusted input needs to be traced, because any
checkpoint the attacker can influence -- a downloaded model, a dataset shard --
executes code on load. This is the ray CVE-2026-57516 shape, where the bytes come
from iterating a function parameter, so no taint source exists to seed a dataflow
rule even though torch.load is a modeled sink.
"""
import io

import torch


def decode_shard(sample):
    out = dict(sample)
    for key, value in sample.items():
        if key.endswith(".pt"):
            out[key] = torch.load(io.BytesIO(value), weights_only=False)
    return out
