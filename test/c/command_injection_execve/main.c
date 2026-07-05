/* getenv -> execve: an attacker-controlled program path passed to the exec
   family is command injection even without a shell. */
#include <stdlib.h>
#include <unistd.h>
int main(void) {
    char *prog = getenv("PROG");           /* untrusted */
    char *argv[] = {prog, 0};
    char *envp[] = {0};
    if (prog) execve(prog, argv, envp);    /* sink */
    return 0;
}
