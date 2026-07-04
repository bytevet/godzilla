// SSRF: an untrusted request parameter is the full URL of an outbound request,
// so the attacker controls the host/authority.
import javax.servlet.http.HttpServletRequest;
import java.net.URL;
public class Handler {
    public void handle(HttpServletRequest req) throws Exception {
        String target = req.getParameter("url");  // untrusted, attacker-controlled host
        URL u = new URL(target);                   // SSRF sink
        u.openConnection();
    }
}
