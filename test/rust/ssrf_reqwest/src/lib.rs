// Opt-in real-crate sample: a reqwest handler makes an outbound HTTP request to a
// URL taken from an untrusted HTTP query parameter — SSRF (CWE-918). Needs cargo
// + network to fetch reqwest, so the corpus gates it behind GODZILLA_RUST_E2E=1.
// Verifies detection against the real reqwest::blocking::get API.
mod http {
    pub struct Request;
    impl Request { pub fn query(&self, _n: &str) -> String { String::new() } }
}

pub fn handle(req: &http::Request) {
    let url = req.query("url");
    let _ = reqwest::blocking::get(url.as_str());
}
