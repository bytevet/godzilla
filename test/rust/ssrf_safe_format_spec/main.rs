// Safe SSRF sentinel, guarding the FORMAT-TEMPLATE DECODE rather than the taint
// logic: identical to ssrf_safe_format except the placeholder carries a width
// specifier. rustc encodes a spec-bearing argument with a control byte the MIR
// decoder does not model, and treating that as a failed decode left an empty
// template — which reads as "this format string contains no host" and fired a
// high-confidence CWE-918 on code the plain `{}` form proves safe. Must produce
// ZERO findings.
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
    let url = format!("https://api.internal.example.com/v1/{:>10}", p);
    client.get(&url); // fixed host; taint confined to the path
}
