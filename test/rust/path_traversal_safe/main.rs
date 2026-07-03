// Safe sample / false-positive sentinel for rust-path-traversal.
//
// Untrusted input IS read from an HTTP header, but it never reaches a filesystem
// path — it is only logged. The file that IS opened uses a fixed, constant path.
// The scanner must report ZERO findings here.
mod http {
    pub struct Request;
    impl Request {
        pub fn header(&self, _n: &str) -> String { String::new() }
        pub fn query(&self, _n: &str) -> String { String::new() }
        pub fn body(&self) -> String { String::new() }
    }
}

use std::fs;

pub fn handle(req: &http::Request) {
    let ua = req.header("User-Agent"); // tainted...
    println!("request from {}", ua); // ...but only logged, never a path

    let config = fs::read_to_string("/etc/app/config.toml").unwrap(); // fixed path
    println!("{}", config);
}
