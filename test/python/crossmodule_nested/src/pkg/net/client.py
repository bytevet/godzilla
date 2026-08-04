"""A helper one package deep. The caller imports it by the path relative to the
PACKAGE root (`pkg.net.client`), not to the scan root (`src/pkg/net/client`)."""
import requests


def fetch(url):
    return requests.get(url)
