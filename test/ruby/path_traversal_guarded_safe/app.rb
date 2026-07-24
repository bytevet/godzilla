# Flow-sensitive FP guard (ENG-9), direct-predicate dominator case — proves the
# dominator-based guard analysis (internal/analysis/guards.go) now engages for the
# Ruby frontend's real CFG (Phase 4). The untrusted filename is checked with the
# containment predicate safe_path? on an IF whose TRUE branch DOMINATES the
# File.read sink, so the read is reached only after the path was validated as
# contained. Correctly suppressed; a flow-insensitive engine would flag it.
# (Uses the direct `if safe_path?(name)` form: the Ruby frontend has no unary-`!`
# node, so a `!`/`unless` guard would not trace to the validator — see Phase 4.)
def show(params)
  name = params[:file]
  if safe_path?(name)
    File.read(name)   # sink dominated by the validated (true) branch
  end
end
