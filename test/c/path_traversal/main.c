/* Path traversal: an untrusted filename is opened directly. */
#include <stdio.h>
#include <stdlib.h>
int main(void) {
    char *f = getenv("FILE");   /* source */
    FILE *fp = fopen(f, "r");   /* sink */
    if (fp) fclose(fp);
    return 0;
}
