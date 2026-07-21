# Inter-procedural path traversal through same-class helper methods (implicit
# self). The controller action reads a request param and passes it to a helper
# (arg->param), and a second action pulls the param through a helper's RETURN
# value -- both must link caller->callee for the File.read sink to fire.
class FilesController < ApplicationController
  def show
    name = params[:name]
    read_file(name)              # arg -> param interproc
  end

  def read_file(fname)
    File.read("/data/" + fname)  # sink
  end

  def download
    p = lookup_path             # return-value interproc (bare 0-arg call)
    File.read(p)                # sink
  end

  def lookup_path
    params[:p]                  # implicit return of request data
  end
end
