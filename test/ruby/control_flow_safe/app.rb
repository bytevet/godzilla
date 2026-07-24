# Safe control: the branch body is now traversed, but the command is built only
# from a constant host, so no untrusted data reaches the shell — nothing fires.
def handle(req)
  if req.params[:debug]
    host = "127.0.0.1"
    system("ping -c 1 " + host)
  end
end
