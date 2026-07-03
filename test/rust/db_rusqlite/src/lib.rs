// Opt-in real-crate sample: a rusqlite handler formats an untrusted HTTP query
// parameter into the SQL string instead of binding it — SQL injection (CWE-89).
// Needs cargo + network to fetch rusqlite, so the corpus gates it behind
// GODZILLA_RUST_E2E=1 (like web_rouille). Verifies detection against the real
// rusqlite::Connection::execute API, not a stub.
use rusqlite::Connection;

mod http {
    pub struct Request;
    impl Request { pub fn query(&self, _n: &str) -> String { String::new() } }
}

pub fn handle(req: &http::Request, conn: &Connection) {
    let id = req.query("id");
    let sql = format!("SELECT * FROM users WHERE id = {}", id);
    let _ = conn.execute(&sql, []);
}
