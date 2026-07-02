// Safe sample / false-positive sentinel for rust-path-traversal.
//
// Untrusted input IS read from the environment, but it never reaches a
// filesystem path — it is only logged. The file that IS opened uses a fixed,
// constant path. The scanner must report ZERO findings here.
use std::env;
use std::fs;

fn main() {
    let user = env::var("USER").unwrap(); // tainted...
    println!("request from {}", user); // ...but only logged, never a path

    let config = fs::read_to_string("/etc/app/config.toml").unwrap(); // fixed path
    println!("{}", config);
}
