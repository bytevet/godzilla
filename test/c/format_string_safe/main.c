/* Safe: untrusted input is an ARGUMENT to a constant format string, not the
   format itself, so this is not a format-string vulnerability. Zero findings. */
#include <stdio.h>
#include <stdlib.h>
int main(void) {
    char *u = getenv("MSG");
    printf("%s", u);   /* format is constant (arg 0); u is a bound argument */
    return 0;
}
