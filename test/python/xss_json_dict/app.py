"""Django view with a reflected-JSON XSS carried through a CONTAINER.

The container variant of xss_json: the untrusted value is placed in a dict
before being serialized, which is how real code shapes a response body. The
taint therefore has to survive entering the dict, not just the json.dumps hop --
a freshly built container has to carry its elements' taint for this to be found.

This is the shape behind label-studio CVE-2025-47783, whose source
(request.POST.get) and sink (HttpResponse) were both already modeled: the flow
was invisible only because the value travelled inside a dict.
"""
import json

from django.http import HttpResponse


def echo(request):
    value = request.POST.get("label_config")
    payload = {"config": value, "ok": True}
    return HttpResponse(json.dumps(payload))
