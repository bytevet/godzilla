// Safe sample / false-positive sentinel for rust-sql-injection.
//
// The SQL text is a constant and the untrusted value is a BOUND parameter
// (operand 2 of execute), not part of the query string, so this is a
// parameterized query and must produce ZERO findings.
mod http {
    pub struct Request;
    impl Request { pub fn query(&self, _n: &str) -> String { String::new() } }
}
mod db {
    pub struct Connection;
    impl Connection { pub fn execute(&self, _sql: &str, _params: &[&str]) {} }
}

pub fn handle(req: &http::Request, conn: &db::Connection) {
    let id = req.query("id");
    conn.execute("SELECT * FROM users WHERE id = ?", &[id.as_str()]); // bound: safe
}
