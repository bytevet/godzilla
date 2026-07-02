// Vulnerable sample: OS command injection via Command::args (CWE-78).
//
// The tainted value is passed as an argument *vector* (Command::args) rather
// than a single Command::arg — exercising taint flow through an array aggregate
// into the args sink.
use std::env;
use std::process::Command;

fn main() {
    let arg = env::var("ARG").unwrap();
    Command::new("echo").args([&arg]).output().unwrap();
}
