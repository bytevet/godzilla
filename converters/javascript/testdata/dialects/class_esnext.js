// Class-body syntax past ES2022: a static block, `#x in o`, and an auto
// accessor. All three are dropped by the lowering (non-method class members are
// unmodeled), so what this fixture pins is that they PARSE — an unparsed class
// costs the whole file, including its methods.
class Registry {
  #entries = new Map();
  accessor label = "registry";
  static defaults = {};
  static { Registry.defaults = { strict: true }; }

  static owns(o) { return #entries in o; }
  add(k, v) { this.#entries.set(k, v); }
}
module.exports = { Registry };
