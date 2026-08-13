// Syntax that once had to be downlevelled because the parser could not spell it.
// Each construct here cost a real file when it was unreadable, so they are held
// to the same "must convert" bar as every other dialect.
function* ids() { yield 1; }
async function* stream() { yield 1; }
const scaled = 2 ** 3;
const merged = { ...{ x: 1 }, y: 2 };
const big = 1n;
const wide = 1_000_000;
const re = /(?<=a)b/;

try { ids(); } catch { stream(); }

let n = 1;
n ||= 2;
n &&= 3;
n ??= 4;

async function drain(src, cb) {
  for await (const chunk of src) { cb?.(chunk); }
}

function scoped(getRes) { using r = getRes(); return r; }

const here = import.meta.url;
module.exports = { ids, stream, drain, scoped, scaled, merged, big, wide, re, n, here };
