# Safe control: @path is assigned a constant (not request-derived), so the
# cross-method @ivar channel carries no taint and nothing should fire. Proves
# instance-variable modeling does not, on its own, manufacture findings.
class UploadController < ApplicationController
  def stage
    @path = "/srv/app/uploads/default.bin"
  end

  def commit
    File.open(@path, "wb")
  end
end
