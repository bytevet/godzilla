// Command injection in C++: an untrusted HTTP query string (CGI QUERY_STRING)
// flows through std::getenv into std::system. char* primitive value flow (like
// C); C++ routing untrusted data through std::string (heap aggregate) is not yet
// tracked.
#include <cstdlib>
int main() {
    const char *q = std::getenv("QUERY_STRING");   // untrusted HTTP query (CGI)
    std::system(q);                                 // sink
    return 0;
}
