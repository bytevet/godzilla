// Safe: the untrusted value is HTML-escaped (Spring HtmlUtils.htmlEscape) before
// being written to the response, so it must NOT be flagged. Expect zero findings.
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.web.util.HtmlUtils;
public class Handler {
    public void handle(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        String name = req.getParameter("name");
        resp.getWriter().println("<h1>Hi " + HtmlUtils.htmlEscape(name) + "</h1>"); // escaped
    }
}
