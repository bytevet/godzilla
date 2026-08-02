"""Reflected-JSON XSS carried through a CONTAINER (the dict variant of xss_json).

The taint has to survive entering the dict, not just the json.dumps hop. This is
the shape behind label-studio CVE-2025-47783, whose source and sink were both
already modeled -- the flow was invisible only because it travelled in a dict.
"""
import json

from django.http import HttpResponse


def echo(request):
    value = request.POST.get("label_config")
    payload = {"config": value, "ok": True}
    return HttpResponse(json.dumps(payload))
