# A comparison's result is a bool -- influence, not content -- so it must not
# carry its operands' taint into a sink. The Ruby frontend used to discard the
# operator and lower EVERY binary expression as BIN_OP_ADD, the engine's
# universal propagator, so `role == "admin"` laundered request taint exactly as
# concatenation would.
#
# Interpolation is deliberate: it folds parts with BIN_OP_ADD, so the ONLY thing
# standing between the tainted param and the sink is whether the comparison
# propagates. (`#{...}.to_s` would not test this -- Ruby's `.to_s` is not modeled
# as a propagator, so it drops taint on its own and the sample would pass for the
# wrong reason.)
#
# The concatenation in the same handler MUST still fire, which is what stops the
# fix from being "make Ruby binary expressions inert".
def run(params)
  system("logger #{params[:role] == "admin"}")   # bool: must NOT fire
  system("echo " + params[:msg])                 # concatenation: MUST fire
end
