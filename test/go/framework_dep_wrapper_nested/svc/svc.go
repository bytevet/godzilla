package svc
import (
	"github.com/gin-gonic/gin"
	"example.com/requtil"
)
func Fetch(c *gin.Context, key string) string { return requtil.ReadQuery(c, key) } // middle: no source here
