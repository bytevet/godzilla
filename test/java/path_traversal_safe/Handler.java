// Safe / false-positive sentinel for java-path-traversal. Untrusted input is
// read but only logged; the file opened is a fixed, constant path. Also writes a
// tainted PAYLOAD to a fixed path via Files.write (the data arg, not the path,
// carries taint), which must NOT be flagged. Expect ZERO findings.
import javax.servlet.http.HttpServletRequest;
import java.io.FileInputStream;
import java.nio.file.Files;
import java.nio.file.Paths;

public class Handler {
    public void handle(HttpServletRequest req) throws Exception {
        String name = req.getParameter("file");
        System.out.println("requested: " + name);              // logged only
        FileInputStream fis = new FileInputStream("/etc/app/config.properties"); // fixed path
        fis.close();
        byte[] payload = req.getParameter("data").getBytes();  // tainted DATA...
        Files.write(Paths.get("/var/app/out.log"), payload);   // ...to a FIXED path (arg 1, not the path)
    }
}
