// Positive twin of ssrf_safe_format_spec: same spec-bearing `format!`
// placeholder (`{:>10}`, which lowers to the `new_v1_formatted` constructor,
// distinct from the plain `new_v1`/`new_const` forms), but here the untrusted
// value is the HOST, not the path. Must fire — this is what pins that
// ssrf_safe_format_spec is clean because the host is genuinely proven fixed,
// not because taint silently fails to reach the sink at all.
mod http {
    pub struct Request;
    impl Request { pub fn query(&self, _n: &str) -> String { String::new() } }
}
mod http_client {
    pub struct Client;
    impl Client { pub fn get(&self, _url: &str) {} }
}

pub fn handle(req: &http::Request, client: &http_client::Client) {
    let h = req.query("host"); // untrusted, reaches the HOST
    let url = format!("https://{:>10}/v1/path", h);
    client.get(&url); // attacker-controlled host
}
