// Flow-typed .js. Unlike testdata/dialects/flow.js — whose annotations all
// happen to be valid TypeScript, so LoaderTS accepts it — every construct below
// is Flow-ONLY and fails every rung of the loader ladder:
//
//   ?string            a maybe-type; TS has no prefix `?` on a type
//   {[string]: mixed}  an unnamed indexer; TS demands `[k: string]: T`
//   opaque type        not a TS keyword
//   +field             a variance sigil
//
// Modeled on parse-server's PostgresStorageAdapter.js, which is dense in the
// first two and is where its SQL sinks live. esbuild has no Flow loader (its
// Loader enum has no such entry), so this is not a missing-rung problem.
opaque type SessionId = string;

type Options = {
  +readOnly: boolean,
  [string]: mixed,
};

function query(sql: string, opts: ?Options): ?string {
  return opts ? sql : null;
}

module.exports = { query };
