// Path traversal: an untrusted HTTP request parameter is used to build a file
// path opened for reading, so ?file=../../etc/passwd escapes the intended dir.
import javax.servlet.http.HttpServletRequest;
import java.io.FileInputStream;
import java.nio.file.Files;
import java.nio.file.Paths;

public class Handler {
    public void readStream(HttpServletRequest req) throws Exception {
        String name = req.getParameter("file");          // untrusted
        FileInputStream fis = new FileInputStream("/var/data/" + name); // sink
        fis.close();
    }

    public byte[] readNio(HttpServletRequest req) throws Exception {
        String name = req.getParameter("file");          // untrusted
        return Files.readAllBytes(Paths.get("/var/data/" + name)); // sink via Paths.get
    }
}
