# Safe: the argument-list form of system() passes argv directly to execve with
# no shell, so a tainted argument cannot inject shell metacharacters.
def handle(req)
  name = req.params[:name]
  system("ls", name)
end
