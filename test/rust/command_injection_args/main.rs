// Vulnerable sample: OS command injection via a command-line argument (CWE-78).
//
// Exercises the env::args() source flowing through Vec collect + indexing into a
// std::process::Command argument.
use std::env;
use std::process::Command;

fn main() {
    let a: Vec<String> = env::args().collect();
    Command::new("sh").arg("-c").arg(&a[1]).output().unwrap();
}
