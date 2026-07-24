package requtil

import "github.com/gin-gonic/gin"

// ReadQuery is a DEPENDENCY-side wrapper around gin's request accessor.
// The taint SOURCE (c.Query) lives inside this dep function, not user code.
func ReadQuery(c *gin.Context, key string) string {
	return c.Query(key)
}
