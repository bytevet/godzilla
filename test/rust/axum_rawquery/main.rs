// Command injection via an axum RawQuery extractor (CWE-78).
//
// An axum handler can take the raw request query string as a `RawQuery`
// extractor parameter (attacker-controlled). PR3 teaches the Rust frontend to
// synthesize a taint source for this non-generic extractor (alongside the
// generic Query/Path/Json/Form). Here the raw query flows straight into
// `sh -c`, so an attacker controls the executed command.
//
// `RawQuery` is stubbed with a local type of the same name so the sample builds
// with rustc alone; real axum exposes `axum::extract::RawQuery` with the same
// shape, matched by the `rust:axum::extract::RawQuery` source glob.
struct RawQuery(String);

use std::process::Command;

pub fn handle(q: RawQuery) {
    let raw = q.0; // the raw request query string (untrusted)
    let output = Command::new("sh")
        .arg("-c")
        .arg(&raw) // <- tainted argument reaches the command
        .output()
        .unwrap();
    println!("{:?}", output.status);
}

fn main() {
    handle(RawQuery(String::from("id=1")));
}
