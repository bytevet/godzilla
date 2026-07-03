// Vulnerable sample: SQL injection (CWE-89).
//
// An untrusted HTTP query parameter is interpolated into the SQL string with
// format! instead of being bound as a parameter, so ?id=1 OR 1=1 alters the
// query. `http`/`db` are minimal stand-ins for a web framework + a DB driver so
// the sample compiles offline (the opt-in db_rusqlite sample uses a real crate).
mod http {
    pub struct Request;
    impl Request { pub fn query(&self, _n: &str) -> String { String::new() } }
}
mod db {
    pub struct Connection;
    impl Connection {
        // execute(sql, params): the SQL text is operand 1 (the injection point).
        pub fn execute(&self, _sql: &str, _params: &[&str]) {}
    }
}

pub fn handle(req: &http::Request, conn: &db::Connection) {
    let id = req.query("id"); // untrusted
    let sql = format!("SELECT * FROM users WHERE id = {}", id); // tainted SQL text
    conn.execute(&sql, &[]);
}
