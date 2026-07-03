// Vulnerable sample: OS command injection via Command::args (CWE-78).
//
// The untrusted HTTP parameter is passed as an argument *vector* (Command::args)
// rather than a single Command::arg — exercising taint flow through an array
// aggregate into the args sink.
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
    let arg = req.query("arg"); // untrusted HTTP query parameter
    Command::new("echo").args([&arg]).output().unwrap();
}
