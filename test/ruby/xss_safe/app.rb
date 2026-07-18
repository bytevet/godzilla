# Safe: the untrusted value is HTML-escaped via the `h` helper before it reaches
# the `raw` output sink, so no XSS finding must fire.
def render_comment
  comment = params[:comment]
  raw(h(comment))
end
