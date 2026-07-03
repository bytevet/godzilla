/* Command injection: an untrusted HTTP query string (CGI QUERY_STRING) is passed
   to system(), so an attacker controlling the request query gets command
   execution. Under CGI, the web server exposes request params/headers to a C
   program as environment variables (QUERY_STRING, HTTP_*). */
#include <stdlib.h>
int main(void) {
    char *q = getenv("QUERY_STRING");   /* untrusted HTTP query params (CGI) */
    system(q);                          /* sink */
    return 0;
}
