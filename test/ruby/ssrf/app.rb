# SSRF: a request-controlled URL is fetched by the server with no allow-list,
# so an attacker can reach internal hosts.
def fetch
  url = params[:url]
  Net::HTTP.get(url)
end
