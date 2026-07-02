/* Format string: untrusted input used as the printf format. */
#include <stdio.h>
#include <stdlib.h>
int main(void) {
    char *u = getenv("MSG");   /* source */
    printf(u);                 /* sink: user-controlled format string */
    return 0;
}
