// SQL injection: an untrusted HTTP request parameter is concatenated into a JDBC
// query string instead of being bound as a parameter.
import java.sql.Statement;
import javax.servlet.http.HttpServletRequest;
public class Dao {
    public void run(Statement stmt, HttpServletRequest req) throws Exception {
        String id = req.getParameter("id");                       // source
        stmt.executeQuery("SELECT * FROM users WHERE id = " + id); // sink (concat)
    }
}
