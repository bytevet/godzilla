// Insecure deserialization: an untrusted request body stream is deserialized
// with ObjectInputStream, enabling gadget-chain remote code execution.
import javax.servlet.http.HttpServletRequest;
import java.io.ObjectInputStream;
public class Handler {
    public Object handle(HttpServletRequest req) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(req.getInputStream()); // deser sink
        return ois.readObject();
    }
}
