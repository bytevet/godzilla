# Guard tracing must survive a comparison. internal/analysis/guards.go walks a
# branch condition back to the validator call that shaped it; when comparisons
# moved from BIN_OP onto the inert builtin.compare intrinsic (so they would stop
# propagating taint), that walk stopped following them, and an `== true` between
# the validator and the `if` hid the guard.
#
# Not propagating and not being traceable are different properties; only the
# first was intended.
def show(params)
  name = params[:file]
  if safe_path?(name) == true
    File.read(name)   # sink dominated by the validated branch
  end
end
