/* Format string: an untrusted HTTP header (CGI HTTP_USER_AGENT) is used as the
   printf format string, which lets an attacker read/write memory via %n etc. */
#include <stdio.h>
#include <stdlib.h>
int main(void) {
    char *ua = getenv("HTTP_USER_AGENT");   /* untrusted HTTP header (CGI) */
    printf(ua);                             /* sink: user-controlled format */
    return 0;
}
