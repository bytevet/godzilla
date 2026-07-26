"""Django view with a reflected-JSON XSS vulnerability.

read an untrusted request parameter, JSON-serialize it, and write the result
straight into the response body. When such a body is returned without a safe
content type (the default HttpResponse content type is text/html), the reflected
value executes as HTML/script in the victim's browser -- a reflected XSS.

The taint has to survive the json.dumps() hop for this to be detected: json.dumps
returns a string that still contains the argument's data verbatim, so it forwards
taint from its argument to its result (modeled as a py-xss propagator).
"""
import json

from django.http import HttpResponse


def echo(request):
    value = request.POST.get("value")
    return HttpResponse(json.dumps(value))
