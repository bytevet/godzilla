// Top-level await is legal only in an ES module, so it is unreachable for any
// pipeline that consumes CommonJS. Parsing the module as written is what makes
// it readable, and this pins that it stays so.
export const config = await Promise.resolve({ debug: true });
