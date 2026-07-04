/* SQL injection (CWE-89): untrusted input reaches the query string passed to
   mysql_query. The driver function is declared extern so the fixture compiles
   without libmysqlclient (only the call's canonical name matters). The sink pins
   the query argument (#1), not the connection handle (#0). */
#include <stdlib.h>
extern int mysql_query(void *conn, const char *stmt);
int main(void) {
    char *name = getenv("QUERY");          /* untrusted */
    return mysql_query((void *)0, name);   /* sink #1: the query string */
}
