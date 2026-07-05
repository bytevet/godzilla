package javax.servlet.http;
// Minimal stub of the Servlet API's HttpServletRequest so the fixture compiles
// with the JDK alone (no servlet jar on the classpath). Only the accessor
// signatures matter — the analyzer treats getParameter/getHeader as taint sources
// (the runtime-visible type name javax/servlet/http/HttpServletRequest is what the
// rule matches).
public interface HttpServletRequest {
    String getParameter(String name);
    String getHeader(String name);
    String getQueryString();
}
