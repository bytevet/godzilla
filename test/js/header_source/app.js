// Untrusted value from a request HEADER reaches a command sink (COV-6).
const cp = require("child_process");

app.get("/run", (req, res) => {
    const cmd = req.headers["x-run"]; // untrusted header
    cp.execSync(cmd);                 // sink
    res.end("ok");
});
