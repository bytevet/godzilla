/* Safe counterpart to buffer_overflow: the untrusted data is copied with the
   bounded strncpy (a propagator, not an overflow sink) and never reaches an
   unbounded write, so no c-buffer-overflow finding should fire. */
#include <stdlib.h>
#include <string.h>
int main(void) {
    char dst[16];
    char *src = getenv("DATA");
    if (src) {
        strncpy(dst, src, sizeof(dst) - 1);
        dst[sizeof(dst) - 1] = 0;
    }
    return dst[0];
}
