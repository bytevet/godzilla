// Vulnerable sample: path traversal (CWE-22).
//
// A filename taken from the environment is interpolated into a path with
// format! and opened, so $FILE = "../../etc/passwd" escapes the data directory.
use std::env;
use std::fs;

fn main() {
    let name = env::var("FILE").unwrap();
    let path = format!("/var/data/{}", name); // taint flows through format!
    let contents = fs::read_to_string(&path).unwrap();
    println!("{}", contents);
}
