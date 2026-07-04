# Command injection via a backtick literal inside a Sinatra route block: the
# interpolated request parameter reaches a shell.
get "/ping" do
  host = params[:host]
  `ping -c 1 #{host}`
end
