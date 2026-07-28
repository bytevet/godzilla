export class Store {
  #secret = 1;
  static config = {};
  get(o) { return o?.a?.b ?? this.#secret; }
}
