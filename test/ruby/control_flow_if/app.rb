# Command injection reachable only inside an `if` branch. The untrusted request
# parameter is read AND passed to a single-string Kernel#system (a shell) wholly
# within the guarded body — code that the straight-line lowering used to drop,
# because `if` had no handler and the branch body was never traversed.
def handle(req)
  if req.params[:debug]
    host = req.params[:host]
    system("ping -c 1 " + host)
  end
end
