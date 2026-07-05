// TypeScript command injection: type annotations (: string, : void, the Request
// interface) must be stripped by esbuild so goja can parse it, and the finding
// must point at THIS .ts file at the correct line.
const cp = require("child_process");

interface Req {
    query: Record<string, string>;
}

app.get("/run", (req: Req, res: unknown): void => {
    const cmd: string = req.query.cmd;  // untrusted
    cp.execSync(cmd);                    // sink
});
