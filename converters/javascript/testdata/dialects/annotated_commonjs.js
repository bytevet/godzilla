// Type annotations in a .js file with no import/export anywhere: goja rejects it
// at the first `:`, but nothing in the source looks like a module, so a
// syntax-sniffing pre-check sees "plain script" and never runs the transform.
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
