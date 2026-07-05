// Cross-function taint through an instance method: an untrusted request param
// is passed as the LAST argument of runner.run(...), where the receiver-aware
// mapping lands it in the sink parameter `cmd`. Requires the interprocedural
// INVOKE arg->param mapping to account for the receiver (Params[0] == `this`).
import javax.servlet.http.HttpServletRequest;
public class Handler {
    public void handle(HttpServletRequest req) throws Exception {
        String cmd = req.getParameter("cmd"); // untrusted
        Runner runner = new Runner();
        runner.run("prefix", cmd);            // tainted arg is the sink param
    }
}
