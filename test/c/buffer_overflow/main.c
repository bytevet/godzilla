/* Buffer overflow (CWE-120): untrusted environment data is strcpy'd into a
   fixed-size stack buffer with no bounds check. */
#include <stdlib.h>
#include <string.h>
int main(void) {
    char dst[16];
    char *src = getenv("DATA");   /* untrusted */
    if (src) strcpy(dst, src);    /* sink: unbounded copy */
    return dst[0];
}
