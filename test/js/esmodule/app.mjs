// ES module (import/export) command injection. A named import binds its sink
// through the import-alias table (aliases.go), not through a require, so the
// call must still canonicalize to js:child_process.execSync -- that table is the
// only thing standing between an ESM project and no module-anchored sinks at all.
import { execSync } from "child_process";

export function run(req) {
    const cmd = req.query.cmd;  // untrusted
    execSync(cmd);              // sink (imported binding)
}
