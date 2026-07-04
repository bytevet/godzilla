# SQL injection: an untrusted parameter is interpolated into a raw SQL string
# passed to ActiveRecord's connection.execute.
def show(req)
  id = req.params[:id]
  ActiveRecord::Base.connection.execute("SELECT * FROM users WHERE id = #{id}")
end
