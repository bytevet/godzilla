# Safe control for the structural rewrite: `config` is an ordinary handler
# parameter, not a request object. Even though its accessor is named `query`
# (a real request accessor name), the base name is not a request receiver, so
# the opaque-base heuristic does NOT synthesize a taint source here — proving
# the rewrite stays base-scoped and does not over-synthesize sources.
def render_report(config)
  name = config.query
  system("generate_report " + name)
end
