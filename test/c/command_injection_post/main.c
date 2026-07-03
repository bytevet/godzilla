/* Command injection via an HTTP POST body: under CGI the request body is
   delivered on stdin. fgets returns the filled buffer (a taint source), which is
   passed to system(). */
#include <stdio.h>
#include <stdlib.h>
int main(void) {
    char body[256];
    char *line = fgets(body, sizeof(body), stdin);   /* untrusted HTTP body (CGI) */
    if (line) system(line);                          /* sink */
    return 0;
}
