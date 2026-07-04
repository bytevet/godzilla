// Safe / false-positive sentinel for the receiver-aware INVOKE mapping. The
// untrusted value is passed as `label` (never reaches the sink); the executed
// command is a constant. Expect ZERO findings — proves the shifted mapping is
// precise and does not taint the wrong parameter.
import javax.servlet.http.HttpServletRequest;
public class Handler {
    public void handle(HttpServletRequest req) throws Exception {
        String tainted = req.getParameter("x"); // untrusted, but only labels
        Runner runner = new Runner();
        runner.run(tainted, "ls");              // sink runs the constant, not `tainted`
    }
}
