// Open redirect: an untrusted request parameter is used as the redirect target.
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
public class Handler {
    public void handle(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        String next = req.getParameter("next"); // untrusted
        resp.sendRedirect(next);                // open-redirect sink
    }
}
