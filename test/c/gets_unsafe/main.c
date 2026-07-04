/* gets() cannot bound its read and is a defect regardless of dataflow
   (CWE-242). Declared extern so the fixture compiles on toolchains where gets
   has been removed from <stdio.h>; only the call's canonical name matters. */
extern char *gets(char *s);
char buf[64];
int main(void) {
    gets(buf);
    return buf[0];
}
