# Path traversal: a request-controlled filename is read straight off disk with
# no containment check, so a "../" sequence escapes the intended directory
# (mirrors Redmine's CVE-2021-31863 attachment path handling).
def download
  path = params[:path]
  File.read(path)
end
