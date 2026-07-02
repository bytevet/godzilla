// Command injection in C++: std::getenv / std::system are the C functions, so a
// tainted char* flows directly (primitive value flow, like C). C++ code that
// routes untrusted data through std::string (heap aggregate) is not yet tracked.
#include <cstdlib>
int main() {
    const char *cmd = std::getenv("CMD");   // source
    std::system(cmd);                        // sink
    return 0;
}
