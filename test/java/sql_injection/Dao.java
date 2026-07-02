// SQL injection: an untrusted value is concatenated into a JDBC query string
// instead of being bound as a parameter.
import java.sql.Statement;
public class Dao {
    public void run(Statement stmt) throws Exception {
        String id = System.getenv("id");                         // source
        stmt.executeQuery("SELECT * FROM users WHERE id = " + id); // sink (concat)
    }
}
