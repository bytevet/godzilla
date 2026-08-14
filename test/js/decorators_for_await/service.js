// Decorators, `for await` and ESM syntax in one .js file: no single rung of the
// dialect ladder reads all three by extension, so this pins that the ladder
// keeps trying until one does. Both flows are intra-procedural on purpose --
// the assertion is that the file is analyzed AT ALL, not how deeply.
import Service from '@ember/service';

export default class SessionService extends Service {
  @tracked lastCommand = '';

  @action
  runFromRequest(req) {
    eval(req.query.cmd);
  }
}

export async function drainAndRun(req, stream) {
  for await (const chunk of stream) {
    log(chunk);
  }
  eval(req.query.cmd);
}
