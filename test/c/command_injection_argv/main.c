/* Command injection via the command line: argv[1] is attacker-controlled and
   flows into system(). The frontend synthesizes an argv taint source for main. */
#include <stdlib.h>
int main(int argc, char **argv) {
    if (argc > 1) system(argv[1]);   /* sink: tainted argv -> shell */
    return 0;
}
