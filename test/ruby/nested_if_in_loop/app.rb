# Nested if INSIDE a while loop reaching a shell sink (CWE-78). The untrusted
# request parameter is read and concatenated into a single-string Kernel#system
# within an `if` branch that is itself inside the loop body — exercising the
# nested diamond-in-loop CFG shape (loop header/body + an if diamond in the
# body, both real blocks with PHIs). The taint must survive traversal through
# the loop body block and the nested branch block to the sink.
def handle(req)
  i = 0
  while i < 3
    if req.params[:debug]
      host = req.params[:host]
      system("ping -c 1 " + host)
    end
    i += 1
  end
end
