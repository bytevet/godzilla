"""An app with its own dispatch layer: routes are a bare HTTP verb next to an
access-control decorator, never `@app.post`. pyload's JSON API is this shape
(CVE-2026-35187 — SSRF in parse_urls), and a bare verb alone is too weak a
signal to route on, so the access-control decorator is what admits it."""
import requests


def post(fn):
    return fn


def permission(perm):
    def deco(fn):
        return fn

    return deco


class Api:
    @permission("ADD")
    @post
    def parse_urls(self, html=None, url=None):
        return requests.get(url)


class Helper:
    # A bare verb with no access-control decorator alongside it is NOT a route:
    # `post` here is an ordinary helper decorator, and seeding its parameters
    # would taint every such method in the program.
    @post
    def fetch(self, url=None):
        return requests.get(url)
