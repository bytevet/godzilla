# Path traversal through FileUtils / Dir.glob (CWE-22). A request-controlled
# source path is passed straight to FileUtils.cp (which copies a file the
# attacker names), and an attacker-controlled glob pattern is expanded with
# Dir.glob -- both escape the intended directory with a "../" sequence.
class BackupController < ApplicationController
  def restore
    src = params[:src]
    FileUtils.cp(src, "/var/app/current")   # path traversal (sink)
  end

  def list
    pattern = params[:pattern]
    Dir.glob(pattern)                        # glob-pattern traversal (sink)
  end
end
