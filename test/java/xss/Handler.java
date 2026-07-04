// Reflected XSS: an untrusted request parameter is written into the HTTP
// response body without HTML-escaping.
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
public class Handler {
    public void handle(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        String name = req.getParameter("name");                 // untrusted
        resp.getWriter().println("<h1>Hi " + name + "</h1>");   // XSS sink (unescaped)
    }
}
