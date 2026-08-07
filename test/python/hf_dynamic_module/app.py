"""Loading a model whose repository carries its own Python."""
from transformers.dynamic_module_utils import (
    get_class_from_dynamic_module,
    try_get_class_from_dynamic_module,
)


# The caller forwards the trust decision, so this load has a gate.
def load(cfg):
    return get_class_from_dynamic_module(
        cfg.auto_map["AutoModel"], cfg.model, trust_remote_code=cfg.trust_remote_code
    )


# No trust decision reaches the load: whoever picks cfg.model picks what runs.
def load_optional(cfg):
    return try_get_class_from_dynamic_module(cfg.auto_map["AutoModel"], cfg.model)


# A constant repo id is still remote code, and still ungated.
def load_pinned():
    return get_class_from_dynamic_module("modeling.MyModel", "org/pinned-repo")
