# Command injection inside a `while` loop body. The tainted request parameter is
# concatenated into a single-string Kernel#system from within the loop, whose
# body the straight-line lowering used to drop (no `while` handler).
def handle(req)
  i = 0
  while i < 3
    system("ping -c 1 " + req.params[:host])
    i += 1
  end
end
