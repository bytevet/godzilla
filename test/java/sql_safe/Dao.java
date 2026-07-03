// Safe: a parameterized PreparedStatement. The untrusted HTTP parameter is a
// bound "?" parameter, not part of the query string, so this is not SQL injection
// and must produce ZERO findings (the parameterized-query false-positive guard).
import java.sql.Connection;
import java.sql.PreparedStatement;
import javax.servlet.http.HttpServletRequest;
public class Dao {
    public void run(Connection c, HttpServletRequest req) throws Exception {
        String id = req.getParameter("id");
        PreparedStatement ps = c.prepareStatement("SELECT * FROM users WHERE id = ?");
        ps.setString(1, id);   // bound parameter: safe
        ps.executeQuery();
    }
}
