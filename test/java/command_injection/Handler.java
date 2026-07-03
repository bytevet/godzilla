// Command injection: an untrusted HTTP request parameter is concatenated into a
// shell command passed to Runtime.exec. The Servlet API is stubbed alongside
// (javax/servlet/http/HttpServletRequest.java) so the fixture compiles JDK-only.
import javax.servlet.http.HttpServletRequest;
public class Handler {
    public void handle(HttpServletRequest req) throws Exception {
        String cmd = req.getParameter("cmd");         // untrusted HTTP param
        Runtime.getRuntime().exec("sh -c " + cmd);    // sink (string concat)
    }
}
