# Class-based API whose entry method is named by its ROUTE, not by an HTTP verb.
# Flask-AppBuilder routes @expose("/fetch") to `fetch`, so neither the decorator
# verb table nor the handler verb-method table matched, no parameter was seeded,
# and the SSRF below fired NOWHERE -- the shape behind the superset/label-studio
# campaign misses, where the expected class produced zero findings project-wide.
import requests
from flask_appbuilder.api import BaseApi, expose


class ProxyApi(BaseApi):
    @expose("/fetch/<target>", methods=["GET"])
    def fetch(self, target):
        return requests.get(target).text
