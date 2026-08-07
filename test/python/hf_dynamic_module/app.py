"""Loading a model whose repository carries its own Python."""
from transformers.dynamic_module_utils import (
    get_class_from_dynamic_module,
    try_get_class_from_dynamic_module,
)


def load(cfg):
    return get_class_from_dynamic_module(
        cfg.auto_map["AutoModel"], cfg.model, trust_remote_code=cfg.trust_remote_code
    )


def load_optional(cfg):
    return try_get_class_from_dynamic_module(cfg.auto_map["AutoModel"], cfg.model)


# A constant repo id is still remote code: the danger is the load, not the value.
def load_pinned():
    return get_class_from_dynamic_module("modeling.MyModel", "org/pinned-repo")
