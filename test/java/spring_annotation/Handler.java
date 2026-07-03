import java.sql.Statement;

import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestParam;

// Spring-style controller methods whose untrusted parameters are bound via
// @RequestParam / @PathVariable. The analyzer synthesizes a taint source for
// each annotated parameter, so concatenating it into a JDBC query or a shell
// command is flagged. (The two annotations are stubbed alongside so the sample
// compiles with the JDK alone; see RequestParam.java.)
public class Handler {
    Statement stmt;

    public void getUser(@RequestParam String id) throws Exception {
        stmt.executeQuery("SELECT name FROM users WHERE id = '" + id + "'"); // SQL injection
    }

    public void ping(@PathVariable String host) throws Exception {
        Runtime.getRuntime().exec("ping -c1 " + host); // command injection
    }
}
