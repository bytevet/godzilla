"""A dangerous flag reaching a call through a **splat rather than a keyword."""
from langchain_experimental.agents.agent_toolkits.csv.base import create_csv_agent


def dangerous(llm, path):
    agent_kwargs = {"verbose": True, "allow_dangerous_code": True}
    return create_csv_agent(llm, path, **agent_kwargs)


# Resolved from config: the value cannot be read, so a value-guarded rule must
# not claim the flag is on.
def resolved(llm, path, cfg):
    return create_csv_agent(llm, path, **{"allow_dangerous_code": cfg.allow})


def off(llm, path):
    agent_kwargs = {"allow_dangerous_code": False}
    return create_csv_agent(llm, path, **agent_kwargs)


# Rebound after the literal, so the dict the call receives is not the one we can
# see. Expanding the stale literal would let a guard read a value never passed.
def rebound(llm, path, other):
    agent_kwargs = {"allow_dangerous_code": True}
    agent_kwargs = other
    return create_csv_agent(llm, path, **agent_kwargs)
