"""Reflected-JSON XSS carried through a CONTAINER (the dict variant of xss_json).

The taint has to survive entering the dict, not just the json.dumps hop.
"""
import json

from django.http import HttpResponse


def echo(request):
    value = request.POST.get("label_config")
    payload = {"config": value, "ok": True}
    return HttpResponse(json.dumps(payload))
