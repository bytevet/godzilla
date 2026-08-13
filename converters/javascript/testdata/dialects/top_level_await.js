// Top-level await is only legal in an ES module, so it was unreadable for as
// long as the frontend consumed CommonJS: no output format both accepted it and
// could be parsed. Parsing the module directly closes that gap.
export const config = await Promise.resolve({ debug: true });
