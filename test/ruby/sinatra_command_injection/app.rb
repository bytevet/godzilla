# Command injection through a Sinatra request accessor that is OUTSIDE the
# frontend's former fixed request-accessor list. `request` is a free framework
# accessor (an opaque base) and `path_info` was never in the old 7-name member
# whitelist; the structural opaque-base heuristic now treats any accessor off a
# request object as a source, so this untrusted URL path reaches a shell.
get "/run" do
  target = request.path_info
  system("nslookup " + target)
end
