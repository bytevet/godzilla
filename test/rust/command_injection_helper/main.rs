// Vulnerable sample: OS command injection across a function boundary (CWE-78).
//
// The taint enters in `main` (env::var) and reaches the Command sink inside a
// separate helper, so this exercises Godzilla's inter-procedural taint (the
// finding is reported at Medium confidence, per the cross-function rule).
use std::env;
use std::process::Command;

fn run_shell(cmd: &str) {
    Command::new("sh").arg("-c").arg(cmd).output().unwrap();
}

fn main() {
    let user_input = env::var("CMD").unwrap();
    run_shell(&user_input);
}
