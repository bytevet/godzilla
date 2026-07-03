// Safe SSRF sentinel: the untrusted value reaches only the PATH of a fixed host
// (via `String + &str` concatenation, which lowers to `Add::add` and is
// reconstructable), so the request cannot be redirected. ZERO findings.
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
    let url = "https://api.internal.example.com/v1/".to_owned() + &p;
    client.get(&url); // fixed host; taint confined to the path
}
