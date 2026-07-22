# Safe control: FileUtils / Dir.glob operate only on constant, non-request
# paths, so no untrusted input reaches the sink and nothing should fire.
class BackupController < ApplicationController
  def restore
    FileUtils.cp("/etc/app/config.default", "/var/app/current")
  end

  def list
    Dir.glob("/var/app/current/*.log")
  end
end
