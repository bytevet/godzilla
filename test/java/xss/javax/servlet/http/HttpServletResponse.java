package javax.servlet.http;
import java.io.PrintWriter;
// Minimal JDK-only stub of HttpServletResponse; getWriter/sendRedirect are the
// XSS / open-redirect sinks the rules match by runtime type name.
public interface HttpServletResponse {
    PrintWriter getWriter();
    void sendRedirect(String location);
}
