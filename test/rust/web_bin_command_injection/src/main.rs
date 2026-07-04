// A plain binary crate (src/main.rs) — the shape FE-3 fixes: cargo builds it via
// `--bin`, not `--lib`. Untrusted CLI/env input flows into a shell command.
use std::process::Command;

fn main() {
    let cmd = std::env::var("CMD").unwrap();
    let _ = Command::new("sh").arg("-c").arg(&cmd).status();
}
