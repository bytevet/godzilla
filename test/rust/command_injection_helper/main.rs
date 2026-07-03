// Vulnerable sample: OS command injection across a function boundary (CWE-78).
//
// The taint enters in `handle` (an untrusted HTTP query parameter) and reaches
// the Command sink inside a separate helper, exercising Godzilla's
// inter-procedural taint (reported at Medium confidence, per the cross-function
// rule).
mod http {
    pub struct Request;
    impl Request {
        pub fn header(&self, _n: &str) -> String { String::new() }
        pub fn query(&self, _n: &str) -> String { String::new() }
        pub fn body(&self) -> String { String::new() }
    }
}

use std::process::Command;

fn run_shell(cmd: &str) {
    Command::new("sh").arg("-c").arg(cmd).output().unwrap();
}

pub fn handle(req: &http::Request) {
    let user_input = req.query("cmd"); // untrusted HTTP query parameter
    run_shell(&user_input);
}
