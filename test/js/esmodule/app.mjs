// ES module (import/export) command injection: goja cannot parse top-level
// import, so esbuild lowers it to CommonJS first. The named-import call
// execSync(cmd) becomes an interop call (0, import_child_process.execSync)(cmd);
// the sink must still be recognized.
import { execSync } from "child_process";

export function run(req) {
    const cmd = req.query.cmd;  // untrusted
    execSync(cmd);              // sink (imported binding)
}
