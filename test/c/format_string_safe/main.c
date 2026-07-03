/* Safe: the untrusted HTTP header is an ARGUMENT to a constant format string,
   not the format itself, so this is not a format-string vulnerability. Zero
   findings. */
#include <stdio.h>
#include <stdlib.h>
int main(void) {
    char *ua = getenv("HTTP_USER_AGENT");
    printf("%s", ua);   /* format is constant (arg 0); ua is a bound argument */
    return 0;
}
