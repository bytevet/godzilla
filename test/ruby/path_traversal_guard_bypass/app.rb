# Precision control for path_traversal_guarded_safe: SAME validator (safe_path?)
# on the SAME untrusted value, but the check result is ignored and the File.read
# is outside/after the guard, reached on every path. No guard dominates the sink,
# so the taint still reaches it and the finding MUST still fire. Proves the
# dominator suppression is precise (tied to dominance), not a blanket mute.
def show(params)
  name = params[:file]
  safe_path?(name)    # result ignored; does not gate the sink
  File.read(name)     # not dominated by any validated branch -> fires
end
