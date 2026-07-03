// Safe sample / false-positive sentinel.
//
// Untrusted input IS read from an HTTP header, but it only flows to the log, not
// into a command. The command that IS run uses fixed, constant arguments. The
// scanner must report ZERO findings here.
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
    let ua = req.header("User-Agent"); // tainted...
    println!("request from {}", ua); // ...but only logged, never executed

    let output = Command::new("ls").arg("-la").arg("/tmp").output().unwrap();
    println!("{:?}", output.status);
}
