// Vulnerable sample: OS command injection via a split HTTP parameter (CWE-78).
//
// Exercises taint flow through str::split + Vec collect + indexing: an untrusted
// HTTP query parameter is split into an argv and an element reaches the command.
mod http {
    pub struct Request;
    impl Request {
        pub fn header(&self, _n: &str) -> String { String::new() }
        pub fn query(&self, _n: &str) -> String { String::new() }
        pub fn body(&self) -> String { String::new() }
    }
}

use std::process::Command;

pub fn handle(req: &http::Request) {
    let raw = req.query("cmd"); // untrusted HTTP query parameter
    let parts: Vec<&str> = raw.split(' ').collect();
    Command::new("sh").arg("-c").arg(parts[0]).output().unwrap();
}
