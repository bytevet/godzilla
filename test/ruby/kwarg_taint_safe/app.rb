require 'httparty'

# The Rails keyword idioms that made every unpinned sink a false positive once
# keyword values started carrying taint. Each pins one sink's #idx or guard.
class SafeController < ApplicationController
  # A flash message is not the redirect destination.
  def flash_redirect
    redirect_to root_path, notice: params[:msg]
  end

  # filename: is a Content-Disposition header value, not a filesystem path.
  def download
    send_data report_csv, filename: params[:name]
  end

  def serve
    send_file "/srv/report.csv", filename: params[:name]
  end

  # The host is a constant; the tainted value is a query parameter ON it, which
  # is the parameterized form. The rule's `not hostFixed()` guard reads a tainted
  # keyword as a controllable host, so an unpinned sink fires here.
  def api
    HTTParty.get("https://api.example.com/v1/items", query: params[:q])
  end

  # The hash form is parameterized by construction -- the case the inert
  # positional placeholder exists to protect.
  def hash_condition
    User.where(name: params[:q])
  end
end
