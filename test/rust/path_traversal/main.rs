// Vulnerable sample: path traversal (CWE-22).
//
// A filename taken from an untrusted HTTP query parameter is interpolated into a
// path with format! and opened, so `?file=../../etc/passwd` escapes the data
// directory. Taint flows through format!.
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
    let name = req.query("file"); // untrusted HTTP query parameter
    let path = format!("/var/data/{}", name); // taint flows through format!
    let contents = fs::read_to_string(&path).unwrap();
    println!("{}", contents);
}
