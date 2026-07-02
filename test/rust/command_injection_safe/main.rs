// Safe sample / false-positive sentinel.
//
// Untrusted input IS read from the environment, but it only flows to stdout, not
// into a command. The command that IS run uses fixed, constant arguments. The
// scanner must report ZERO findings here.
use std::env;
use std::process::Command;

fn main() {
    let user = env::var("USER").unwrap(); // tainted...
    println!("hello {}", user); // ...but only printed, never executed

    let output = Command::new("ls").arg("-la").arg("/tmp").output().unwrap();
    println!("{:?}", output.status);
}
