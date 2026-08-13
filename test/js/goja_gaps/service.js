// Decorators and `for await` are the two constructs goja's parser cannot spell,
// and a .js file carrying either was previously lost WHOLE -- not analyzed with
// reduced precision, but skipped. This sample is the end-to-end proof that the
// esbuild downlevel recovers the flows inside them.
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
