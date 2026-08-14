function log(_t: unknown, _k: string) {}
function Component(_o: unknown) { return (_c: unknown) => {}; }

@Component({ selector: "svc" })
export class Svc { @log run(cmd: string): void { console.log(cmd); } }
