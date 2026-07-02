/* Command injection: an untrusted environment value is passed to system(). */
#include <stdlib.h>
int main(void) {
    char *cmd = getenv("CMD");   /* source */
    system(cmd);                 /* sink */
    return 0;
}
