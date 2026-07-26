"""FP sentinel: Python introspection is not archive-entry enumeration.

The zip-slip sources must stay receiver-wildcarded (`py:*.getmembers`) because a
real tar handle is a local variable, not the module -- but that glob also matches
inspect.getmembers(), which enumerates a live object's ATTRIBUTES. A plugin
loader or pydoc-shaped module that writes what it inspects is not a zip-slip, so
this must report nothing.
"""
import inspect
import os


def dump_plugin_api(mod, outdir):
    for name, obj in inspect.getmembers(mod):
        with open(os.path.join(outdir, name), "w") as fh:
            fh.write(repr(obj))
