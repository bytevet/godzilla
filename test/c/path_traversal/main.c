/* Path traversal: an untrusted HTTP request path (CGI PATH_INFO) is opened
   directly, so a request path of ../../etc/passwd escapes the intended dir. */
#include <stdio.h>
#include <stdlib.h>
int main(void) {
    char *path = getenv("PATH_INFO");   /* untrusted HTTP request path (CGI) */
    FILE *fp = fopen(path, "r");        /* sink */
    if (fp) fclose(fp);
    return 0;
}
