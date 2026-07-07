import java.sql.Statement;

import javax.ws.rs.QueryParam;
import javax.ws.rs.PathParam;

// JAX-RS resource methods whose untrusted parameters are bound via @QueryParam /
// @PathParam (javax.ws.rs; jakarta.ws.rs is matched by the same java:*ws/rs/*
// globs). The analyzer synthesizes a taint source for each annotated parameter,
// so concatenating it into a JDBC query or a shell command is flagged. The two
// annotations are stubbed alongside so the sample compiles with the JDK alone.
public class Handler {
    Statement stmt;

    public void getUser(@QueryParam("id") String id) throws Exception {
        stmt.executeQuery("SELECT name FROM users WHERE id = '" + id + "'"); // SQL injection
    }

    public void ping(@PathParam("host") String host) throws Exception {
        Runtime.getRuntime().exec("ping -c1 " + host); // command injection
    }
}
