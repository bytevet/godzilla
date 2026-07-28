# Control for fab_expose_route: same framework shape, same sink, but the routed
# parameter never reaches the request URL -- it only selects among fixed targets.
# Seeding @expose methods must not make every Flask-AppBuilder route a finding.
import requests
from flask_appbuilder.api import BaseApi, expose


class ProxyApi(BaseApi):
    @expose("/fetch/<target>", methods=["GET"])
    def fetch(self, target):
        if target == "status":
            return requests.get("https://api.internal.example.com/status").text
        if target == "health":
            return requests.get("https://api.internal.example.com/health").text
        return "unknown target"
