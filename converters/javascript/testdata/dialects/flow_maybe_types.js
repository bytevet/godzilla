// Flow-typed .js. Unlike testdata/dialects/flow.js — whose annotations all
// happen to be valid TypeScript, so the TS rung accepts it — the constructs
// below defeat every rung of the dialect ladder:
//
//   ?string            a maybe-type; TS has no prefix `?` on a type
//   opaque type        not a TS keyword
//
// The unnamed indexer `{[string]: mixed}` and the `+field` variance sigil are
// here as realistic company, not as blockers: tsc would reject both, but the TS
// rung PARSES them, and parsing is all this pipeline does.
//
// Modeled on parse-server's PostgresStorageAdapter.js, which is dense in these
// and is where its SQL sinks live. There is no Flow dialect to add a rung for —
// jsast.Options is TS and JSX, nothing else — so this is not a missing-rung
// problem, and blanking the source is the only lever left.
opaque type SessionId = string;

type Options = {
  +readOnly: boolean,
  [string]: mixed,
};

function query(sql: string, opts: ?Options): ?string {
  return opts ? sql : null;
}

module.exports = { query };
