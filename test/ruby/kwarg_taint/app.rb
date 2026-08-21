# A keyword argument's VALUE carries taint (the frontend appends a builtin.kwarg
# marker per pair); the hash itself stays an inert placeholder in the positional
# slot so an #idx-pinned sink keeps seeing what it saw before.
class ReportsController < ApplicationController
  # render html: interpolates straight into the response body. This is the
  # detection ruby-xss always described and could not make while Ruby erased
  # hashes -- the keyword is the ONLY route from source to sink.
  def unsafe_html
    render html: params[:q]
  end

  # Two keyword shapes on the same sink that must NOT fire: locals feed an
  # auto-escaping template, and a JSON body is not an HTML one.
  def safe_locals
    render partial: "row", locals: params[:opts]
  end

  def safe_json
    render json: params[:q]
  end
end
