// Vulnerable sample: OS command injection (CWE-78).
//
// The command argument comes from an untrusted HTTP query parameter and is
// passed straight to `sh -c`, so an attacker who controls `?host=...` gets
// arbitrary command execution.
//
// `http` is a minimal stand-in for a web framework's request API so the sample
// compiles offline with rustc alone; real frameworks (actix-web, rouille, axum)
// expose the same request-accessor shape, and the opt-in `web_*` sample
// exercises a real crate.
mod http {
    pub struct Request;
    impl Request {
        pub fn header(&self, _name: &str) -> String { String::new() }
        pub fn query(&self, _name: &str) -> String { String::new() }
        pub fn body(&self) -> String { String::new() }
    }
}

use std::process::Command;

pub fn handle(req: &http::Request) {
    let host = req.query("host"); // untrusted HTTP query parameter
    let output = Command::new("sh")
        .arg("-c")
        .arg(&host) // <- tainted argument reaches the command
        .output()
        .unwrap();
    println!("{:?}", output.status);
}
