# Vulnerable: the argument-list form is only safe while argv[0] is not a shell.
# `sh -c` re-interprets what follows, so the untrusted param is executed. The
# pack's old #0 pinning hid this. Pairs with command_injection_safe (`ls`).
require "sinatra"

get "/run" do
  cmd = params[:cmd]           # untrusted request parameter
  system("sh", "-c", cmd)      # argv form, but argv[0] is a shell
end
