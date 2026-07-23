package requtil
import "github.com/gin-gonic/gin"
func ReadQuery(c *gin.Context, key string) string { return c.Query(key) } // innermost: hosts the source
