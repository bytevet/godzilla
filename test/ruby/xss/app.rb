# Reflected XSS: an untrusted request parameter is emitted into the HTML
# response via the `raw` view helper, bypassing Rails' automatic output
# escaping (the same unescaped-markup shape as Redmine's CVE-2023-47258/47259
# formatter XSS).
def render_comment
  comment = params[:comment]
  raw(comment)
end
