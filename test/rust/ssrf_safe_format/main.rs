// Safe SSRF sentinel: the untrusted value reaches only the PATH of a fixed host,
// built with `format!` (the idiomatic Rust string builder). rustc lowers the
// format template to a packed fmt::Arguments byte string; the frontend decodes it
// so the engine can prove the host is constant. Must produce ZERO findings.
mod http {
    pub struct Request;
    impl Request { pub fn query(&self, _n: &str) -> String { String::new() } }
}
mod http_client {
    pub struct Client;
    impl Client { pub fn get(&self, _url: &str) {} }
}

pub fn handle(req: &http::Request, client: &http_client::Client) {
    let p = req.query("path"); // untrusted, but only reaches the path
    let url = format!("https://api.internal.example.com/v1/{}", p);
    client.get(&url); // fixed host; taint confined to the path
}
