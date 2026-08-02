// False-positive sentinel: an argv element handed to a fixed, non-shell program
// is NOT command injection, so this must produce ZERO findings.
//
// `std::process::Command` never invokes a shell — the value reaches execve as one
// argument of `ls`, exactly like the direct-argv form the Python sentinel
// test/python/subprocess_argv_safe covers. The program lives in a different call
// from the argument (`Command::new(...)` vs `.arg(...)`), so the frontend
// forwards it along the builder chain for the rule to read; see rustCommandBuilder
// in converters/rust/mir.go. The vulnerable counterparts are
// command_injection (sh -c) and command_injection_argv (sh with an args vector).
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
    let name = req.query("name"); // untrusted, but only ever one argv element
    Command::new("ls").arg("-la").arg(&name).output().unwrap();
    Command::new("/bin/echo").args([name.as_str()]).output().unwrap();
}
