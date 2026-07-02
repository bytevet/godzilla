// Vulnerable sample: OS command injection (CWE-78).
//
// The command argument is read from an environment variable and passed straight
// to `sh -c`, so an attacker who controls $CMD gets arbitrary command execution.
use std::env;
use std::process::Command;

fn main() {
    let cmd = env::var("CMD").unwrap();
    let output = Command::new("sh")
        .arg("-c")
        .arg(&cmd) // <- tainted argument reaches the command
        .output()
        .unwrap();
    println!("{:?}", output.status);
}
