// Safe: a parameterized PreparedStatement. The untrusted id is a bound "?"
// parameter, not part of the query string, so this is not SQL injection and must
// produce ZERO findings (the parameterized-query false-positive guard).
import java.sql.Connection;
import java.sql.PreparedStatement;
public class Dao {
    public void run(Connection c) throws Exception {
        String id = System.getenv("id");
        PreparedStatement ps = c.prepareStatement("SELECT * FROM users WHERE id = ?");
        ps.setString(1, id);   // bound parameter: safe
        ps.executeQuery();
    }
}
