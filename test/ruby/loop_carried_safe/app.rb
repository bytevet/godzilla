# Safe control for the loop-carried case: same shape as
# loop_carried_command_injection, but the value carried across iterations is a
# CONSTANT, never the tainted request parameter. The header PHI merges two
# constants ("whoami" and "id"), so no untrusted data reaches the shell and
# nothing fires — the false-positive guard for the loop-carried CFG.
def handle(req)
  cmd = "whoami"
  i = 0
  while i < 3
    system(cmd)
    cmd = "id"
    i += 1
  end
end
