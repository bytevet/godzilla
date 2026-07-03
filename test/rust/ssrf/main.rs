// Vulnerable sample: server-side request forgery (CWE-918).
//
// An untrusted HTTP query parameter becomes the URL of an outbound request, so
// ?url=http://169.254.169.254/... reaches internal services. `Client` is a
// minimal stand-in (the opt-in ssrf_reqwest sample uses the real reqwest crate).
mod http {
    pub struct Request;
    impl Request { pub fn query(&self, _n: &str) -> String { String::new() } }
}
mod http_client {
    pub struct Client;
    impl Client { pub fn get(&self, _url: &str) {} }
}

pub fn handle(req: &http::Request, client: &http_client::Client) {
    let target = req.query("url"); // untrusted
    client.get(&target); // outbound request to an attacker-controlled URL
}
