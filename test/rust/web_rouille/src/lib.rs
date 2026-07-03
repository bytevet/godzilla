// Opt-in real-crate sample: a rouille (a real, synchronous Rust web framework)
// handler reads an untrusted HTTP query parameter and passes it to a shell
// command — OS command injection (CWE-78). Because this fetches the framework
// crate over the network, the corpus gates it behind GODZILLA_RUST_E2E=1
// (analogous to Java's spring_boot); it verifies that Godzilla detects the flow
// against a REAL framework's request accessors, not just a stub.
use rouille::Request;
use std::process::Command;

pub fn handle(req: &Request) {
    let host = req.get_param("host").unwrap_or_default(); // untrusted HTTP query param
    Command::new("sh").arg("-c").arg(&host).output().unwrap();
}
