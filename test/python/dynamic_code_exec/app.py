"""Dynamic code execution of a fetched response body (CWE-95).

The evaluated string is not a compile-time constant: it is whatever the remote
service returned. Whoever controls (or can MITM/poison) that endpoint gets
arbitrary Python execution — the shape of llama-index CVE-2024-4181, where an
LLM completion was eval'd.

Note there is no MODELED taint source here on purpose: the URL is a hardcoded
constant, so the dataflow rule py-code-injection cannot fire and only the
call-site rule py-dynamic-code-exec reports this.
"""
import requests

CONFIG_URL = "https://config.internal.example.com/limits"


def load_limits():
    resp = requests.get(CONFIG_URL)
    return eval(resp.text)  # dynamic code execution: not a constant
