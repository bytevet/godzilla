// Vulnerable sample: path traversal via std::fs::File::open (CWE-22).
//
// Unlike path_traversal/ (which builds the path with format!), here the tainted
// filename is opened directly — exercising the File::open sink with no macro in
// between. $FILE = "../../etc/passwd" escapes the intended directory.
use std::env;
use std::fs::File;
use std::io::Read;

fn main() {
    let name = env::var("FILE").unwrap();
    let mut f = File::open(&name).unwrap();
    let mut contents = String::new();
    f.read_to_string(&mut contents).unwrap();
    println!("{}", contents);
}
