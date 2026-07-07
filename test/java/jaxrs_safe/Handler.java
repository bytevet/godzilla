import java.sql.Connection;
import java.sql.PreparedStatement;

import javax.ws.rs.QueryParam;

// False-positive control: a @QueryParam-bound value used safely as a bound
// parameter of a PreparedStatement (never concatenated into the SQL text). The
// analyzer must stay silent here even though @QueryParam is a recognized source.
public class Handler {
    Connection conn;

    public void getUser(@QueryParam("id") String id) throws Exception {
        PreparedStatement ps = conn.prepareStatement("SELECT name FROM users WHERE id = ?");
        ps.setString(1, id); // bound parameter, not part of the query string
        ps.executeQuery();
    }
}
