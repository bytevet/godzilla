// Type annotations in a .js file with no import/export anywhere: nothing here
// looks like a module, so a syntax-sniffing pre-check would call it a plain
// script and stop at the first `:`. Only trying the TS rung recovers it.
// parse-server ships two files of exactly this shape.
class Id {
  className: string;

  constructor(className: string) {
    this.className = className;
  }

  toString(): string {
    return this.className;
  }
}

function label(id: Id, prefix?: string): string {
  return (prefix || '') + id.toString();
}

module.exports = { Id, label };
