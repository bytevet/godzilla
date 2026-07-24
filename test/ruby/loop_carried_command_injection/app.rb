# Loop-CARRIED command injection (CWE-78). `cmd` is passed to Kernel#system at
# the TOP of the while body — BEFORE it is reassigned from the tainted request
# parameter lower in the same body. On the first iteration cmd is the safe
# constant; only the loop's back-edge carries the tainted value from one
# iteration into the next, so the shell call is reachable-tainted ONLY because
# the loop carries cmd across iterations. The old single-block lowering
# flattened the body once, in source order, and saw only the safe constant at
# the sink (a false negative); the real CFG's header PHI (pre-loop value merged
# with the back-edge value) makes the tainted value reach the sink.
def handle(req)
  cmd = "whoami"
  i = 0
  while i < 3
    system(cmd)
    cmd = req.params[:host]
    i += 1
  end
end
