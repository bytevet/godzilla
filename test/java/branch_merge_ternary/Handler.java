// FE-4: a ternary selecting a tainted value must not be dropped. The prior
// linear operand-stack simulation lowered `cond ? tainted : default` by keeping
// only whichever push happened last on the flattened stream — here the "default"
// constant — so the tainted branch was silently lost (a false negative) and the
// stack could misalign past the join. The block-structured simulation now
// PHI-merges the two operand-stack values at the control-flow join, so the
// tainted branch stays live into the Runtime.exec sink.
import javax.servlet.http.HttpServletRequest;

public class Handler {
    public void handle(HttpServletRequest req) throws Exception {
        String name = req.getParameter("host");
        String host = (name == null) ? "localhost" : name;
        Runtime.getRuntime().exec("ping " + host);
    }
}
