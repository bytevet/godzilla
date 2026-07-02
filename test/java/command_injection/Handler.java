// Command injection: an untrusted environment value is concatenated into a shell
// command passed to Runtime.exec. Self-contained (JDK-only APIs) so it compiles
// standalone for the corpus.
public class Handler {
    public void handle() throws Exception {
        String cmd = System.getenv("CMD");            // source
        Runtime.getRuntime().exec("sh -c " + cmd);    // sink (string concat)
    }
}
