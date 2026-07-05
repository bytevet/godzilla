// Safe: the request value is read but the outbound URL is a fixed constant, so
// the attacker cannot redirect the request. Expect zero findings.
import javax.servlet.http.HttpServletRequest;
import java.net.URL;
public class Handler {
    public void handle(HttpServletRequest req) throws Exception {
        String ignored = req.getParameter("url");                       // not used as the URL
        URL u = new URL("http://api.internal.example.com/status");      // fixed host
        u.openConnection();
    }
}
