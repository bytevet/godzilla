// Gin's ShouldBind fills a caller-allocated struct rather than returning the
// untrusted value: it returns only an error, so nothing taints `params` unless
// the source rule names the OUT-PARAMETER it fills (sources: "...ShouldBind#0").
package main

import (
	"os/exec"

	"github.com/gin-gonic/gin"
)

type actionReq struct {
	Cmd string `json:"cmd"`
}

func main() {
	r := gin.Default()
	r.POST("/run", func(c *gin.Context) {
		var params actionReq
		c.ShouldBind(&params)                                   // untrusted body fills params, not the error return
		out, _ := exec.Command("sh", "-c", params.Cmd).Output() // command injection
		c.String(200, string(out))
	})
	_ = r.Run(":8080")
}
