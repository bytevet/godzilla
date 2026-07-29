// Flow-typed .js, second fixture: the constructs that still dropped a file after
// flow_maybe_types.js was already converting. Every one below was found by
// running the stripper over parse-server's whole src tree and reading what
// esbuild still rejected — together they were the last 9 of its 196 files.
//
//   export type / declare export   blanking the keyword alone strands the modifier
//   type T = | a | b               a union continues across newlines
//   (x: T)                         a cast, including nested and on a pattern
//   <T: Bound>                     Flow's generic bound; TS spells it `extends`
//
// The last one is the reason `type` is only a keyword at statement start: React
// names variables `type` everywhere, and `(type as X)` otherwise reads as a type
// alias and blanks the rest of the enclosing function while staying brace-balanced
// — a file that parses and is silently wrong, which is strictly worse than a drop.

// A specifier list is NOT a declaration position; `type` here is a named import.
import { type Config, parse } from './config';

export type SchemaField = { +type: string, targetClass: ?string };

declare export type Handle = number;

type Sort =
  | 'ascending'
  | 'descending'
  | { [string]: number };

class Adapter {
  // a property annotation may follow a comment, or a `static` modifier
  connection: ?Promise<any>;
  static shared: ?Adapter;

  paramsAreEquals<T: { [key: string]: any }>(a: T, b: T): boolean {
    return Object.keys(a).length === Object.keys(b).length;
  }

  sortKeys(where: { sorts: Sort }): number {
    // a cast nested inside a call's arguments
    if (where.sorts && Object.keys((where.sorts: any)).length > 0) {
      return 1;
    }
    return 0;
  }

  normalize(schema: SchemaField): SchemaField {
    // a cast applied to an object literal, not to a bare identifier
    const field = ({ ...schema, targetClass: null }: SchemaField);
    return field;
  }
}

// `type` as an ordinary identifier: an argument, and a declarator initialiser.
function render(type, props) {
  const resolved = type;
  return { type: resolved, props };
}

module.exports = { Adapter, render };
