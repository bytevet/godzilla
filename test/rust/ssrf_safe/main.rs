// Safe sample / false-positive sentinel for rust-ssrf.
//
// Untrusted input IS read from an HTTP header, but it only flows to the log; the
// outbound request uses a fixed, constant URL. The scanner must report ZERO
// findings here.
mod http {
    pub struct Request;
    impl Request {
        pub fn query(&self, _n: &str) -> String { String::new() }
        pub fn header(&self, _n: &str) -> String { String::new() }
    }
}
mod http_client {
    pub struct Client;
    impl Client { pub fn get(&self, _url: &str) {} }
}

pub fn handle(req: &http::Request, client: &http_client::Client) {
    let ua = req.header("User-Agent"); // tainted...
    println!("request from {}", ua); // ...but only logged
    client.get("https://api.internal.example/health"); // fixed URL
}
