"""pycurl sets the request URL as an OPTION, not as a URL-named call, so the
sink is setopt's value argument. This is where an app with its own HTTP layer
bottoms out (pyload, CVE-2026-35187)."""
import pycurl
from flask import request


def fetch():
    url = request.args.get("u")
    c = pycurl.Curl()
    c.setopt(pycurl.URL, url)
    c.perform()


def fetch_fixed():
    c = pycurl.Curl()
    c.setopt(pycurl.URL, "https://example.com/feed")
    c.perform()
