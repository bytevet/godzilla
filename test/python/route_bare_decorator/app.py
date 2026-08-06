"""An app with its own dispatch layer: routes are a bare HTTP verb, never
`@app.post`. pyload's JSON API is this shape (CVE-2026-35187 — SSRF in
parse_urls), 84 bare @get/@post with no dotted form anywhere.

A bare verb alone is far too weak a marker — `post` is an ordinary word. The
SET is not: a class whose methods carry two or more DISTINCT bare verbs is
dispatching, because a one-off helper decorator does not come with a sibling
named after a different verb."""
import requests


def get(fn):
    return fn


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

    # No access-control decorator. An earlier version of this rule keyed on one,
    # which excluded exactly the UNAUTHENTICATED endpoints — the ones most worth
    # seeding. The verb set does not care.
    @get
    def preview(self, url=None):
        return requests.get(url)


class UploadApi(Api):
    # A SINGLE bare verb, which is not evidence on its own. Subclassing a
    # confirmed dispatch layer is: frameworks routinely put the routing surface
    # on a base class and a handful of handlers on each subclass.
    @post
    def upload(self, url=None):
        return requests.get(url)


class Helper:
    # One bare verb, no sibling verb, and no dispatch base: `post` here is an
    # ordinary helper decorator, not a routing table. Seeding its params would
    # taint every such method in the program.
    @post
    def fetch(self, url=None):
        return requests.get(url)
