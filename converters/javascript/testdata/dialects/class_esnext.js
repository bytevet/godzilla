// Class-body syntax past ES2022: private and static fields, a static block,
// `#x in o`, an auto accessor, plus optional chaining and nullish coalescing in
// a method. Non-method class members are unmodeled by the lowering, so what this
// pins is that they PARSE and lower without a fallback — an unparsed class costs
// the whole file, methods included.
export class Registry {
  #entries = new Map();
  accessor label = "registry";
  static defaults = {};
  static { Registry.defaults = { strict: true }; }

  static owns(o) { return #entries in o; }
  add(k, v) { this.#entries.set(k, v); }
  get(o) { return o?.a?.b ?? this.#entries; }
}
