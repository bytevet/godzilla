package requtil

import "github.com/gin-gonic/gin"

// SafeInput reads the request accessor but returns a CONSTANT, so no taint
// escapes. Seeding this host must NOT produce a false positive: its body has no
// tainted return, so nothing propagates to the caller.
func ReadQuery(c *gin.Context, key string) string {
	_ = c.Query(key) // read, but not returned
	return "safe-constant"
}
