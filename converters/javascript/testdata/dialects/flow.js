// @flow
type Options = { host: string };
export interface Runner { go(o: Options): void }
export function ping(host: string, opts?: Options): void { console.log(host, opts); }
