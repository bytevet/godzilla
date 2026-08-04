"""The sink, one package deep."""
import requests


def fetch(url):
    return requests.get(url)
