// False-positive control for PR3's Rust extractor widening.
//
// A bare `String` (or `Bytes`) handler parameter is NOT treated as a taint
// source: those types are far too common to seed safely, so the frontend
// deliberately synthesizes a source only for the axum-specific extractor type
// names (Query/Path/Json/Form/RawQuery/RawForm), never for `String`. Here a
// plain `String` parameter flows into `sh -c`, and the scanner must stay silent
// — proving `String`/`Bytes` were correctly omitted.
use std::process::Command;

pub fn handle(body: String) {
    let output = Command::new("sh")
        .arg("-c")
        .arg(&body)
        .output()
        .unwrap();
    println!("{:?}", output.status);
}

fn main() {
    handle(String::from("echo hi"));
}
