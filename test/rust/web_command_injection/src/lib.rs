// Hermetic Cargo sample: exercises the frontend's Cargo build path
// (`cargo rustc -- --emit=mir`) offline, with no external dependencies. A local
// `http` module stands in for a web framework's request API; the opt-in
// `web_actix` sample uses a real crate. CWE-78.
mod http {
    pub struct Request;
    impl Request {
        pub fn header(&self, _n: &str) -> String { String::new() }
        pub fn query(&self, _n: &str) -> String { String::new() }
    }
}

use std::process::Command;

pub fn handle(req: &http::Request) {
    let host = req.query("host"); // untrusted HTTP query parameter
    Command::new("sh").arg("-c").arg(&host).output().unwrap();
}
