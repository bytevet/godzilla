# Ruby's classic RCE class: Marshal and unsafe YAML rebuild an object graph, so
# a crafted payload runs code during load without any eval.
class ImportsController < ApplicationController
  def marshal_blob
    Marshal.load(params[:blob])
  end

  def unsafe_yaml
    YAML.load(params[:cfg])
  end

  # The safe loaders parse the same formats without instantiating arbitrary
  # classes, so a value through them carries no object-graph payload.
  def safe_yaml
    YAML.safe_load(params[:cfg])
  end

  def json
    JSON.parse(params[:cfg])
  end

  # A constant path is not attacker-controlled.
  def fixture
    Marshal.load(File.read("fixture.bin"))
  end
end
