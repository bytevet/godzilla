// The untrusted value is transformed by a String METHOD (.toLowerCase()), so
// the taint is on the receiver, not an argument. The default propagator plus
// receiver-aware propagation must carry it into the sink (ENG-4).
const cp = require("child_process");

app.get("/run", (req, res) => {
    const cmd = req.query.cmd.toLowerCase(); // taint through a receiver-method transform
    cp.execSync(cmd);                        // sink
    res.end("ok");
});
