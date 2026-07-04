// FE-5 (Rust): the "default if empty" pattern must not drop taint. MIR is not
// SSA — rustc reassigns the same local (`host`) in the if-arm, and the prior
// linear flattener let that constant reassignment clobber the tainted binding,
// so the post-join Command::arg sink read the constant (a false negative). The
// block-structured lowering now PHI-merges `host` at the control-flow join, so
// the tainted path stays live into the sink.
use std::process::Command;

fn main() {
    let mut host = std::env::args().nth(1).unwrap();
    if host.is_empty() {
        host = String::from("localhost");
    }
    Command::new("ping").arg(host).status().unwrap();
}
