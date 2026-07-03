// Vulnerable sample: path traversal via std::fs::File::open (CWE-22).
//
// Unlike path_traversal/ (which builds the path with format!), here the untrusted
// HTTP filename is opened directly — exercising the File::open sink with no macro
// in between. `?file=../../etc/passwd` escapes the intended directory.
mod http {
    pub struct Request;
    impl Request {
        pub fn header(&self, _n: &str) -> String { String::new() }
        pub fn query(&self, _n: &str) -> String { String::new() }
        pub fn body(&self) -> String { String::new() }
    }
}

use std::fs::File;
use std::io::Read;

pub fn handle(req: &http::Request) {
    let name = req.query("file"); // untrusted HTTP query parameter
    let mut f = File::open(&name).unwrap();
    let mut contents = String::new();
    f.read_to_string(&mut contents).unwrap();
    println!("{}", contents);
}
