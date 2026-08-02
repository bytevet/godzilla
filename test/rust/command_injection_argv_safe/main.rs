// FP sentinel: an argv element handed to a fixed, non-shell program is not
// command injection — `Command` never invokes a shell, so the value reaches
// execve as one argument of `ls`. Must produce ZERO findings. The vulnerable
// counterparts are command_injection (sh -c) and command_injection_argv.
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
