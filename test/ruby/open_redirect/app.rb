# Open redirect: a request-controlled URL flows into redirect_to with no
# allow-list / only_path restriction, so the victim can be sent to any site.
def go
  target = params[:url]
  redirect_to target
end
