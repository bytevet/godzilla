# Command injection: an untrusted request parameter is concatenated into a shell
# command passed to Kernel#system (single-string form invokes a shell).
def handle(req)
  host = req.params[:host]
  system("ping -c 1 " + host)
end
