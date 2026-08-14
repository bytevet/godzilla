// TypeScript command injection: type annotations (: string, : void, the Request
// interface) are erased by the ladder's TS rung, and the finding must still point
// at THIS .ts file at the correct line -- an erased annotation shifts no offset.
const cp = require("child_process");

interface Req {
    query: Record<string, string>;
}

app.get("/run", (req: Req, res: unknown): void => {
    const cmd: string = req.query.cmd;  // untrusted
    cp.execSync(cmd);                    // sink
});
