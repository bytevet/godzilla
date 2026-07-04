package javax.servlet.http;
import java.io.InputStream;
// Minimal JDK-only stub of the Servlet API so fixtures compile without a servlet
// jar. The runtime-visible type name javax/servlet/http/HttpServletRequest is
// what the source rules match.
public interface HttpServletRequest {
    String getParameter(String name);
    String getHeader(String name);
    String getQueryString();
    InputStream getInputStream();
}
