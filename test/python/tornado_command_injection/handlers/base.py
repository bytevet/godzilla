"""Project base handler in a separate file from the concrete handler, so the
handler-class recognition must resolve subclassing across module boundaries."""
from tornado.web import RequestHandler


class BaseHandler(RequestHandler):
    pass
