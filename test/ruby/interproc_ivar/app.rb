# Cross-method instance-variable taint: one action stashes untrusted request
# input into @path, a SEPARATE action reads @path and passes it to a file sink.
# Taint must persist across methods of the same class via the @ivar.
class UploadController < ApplicationController
  def stage
    @path = params[:path]   # stash untrusted input on the instance
  end

  def commit
    File.open(@path, "wb")  # sink; taint read back from @path cross-method
  end
end
