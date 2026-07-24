package main

// The taint SOURCE (gin's c.Query) lives inside a DEPENDENCY wrapper
// (example.com/requtil.ReadQuery), not in user code. The accessor globs taint the
// call RESULT, not the context, so the wrapper takes no tainted argument; without
// seeding dep functions that host a source (buildReqSourceHosts generalized to all
// sources), the demand-driven scope never analyses the wrapper and the flow is a
// false negative. This guards that fix.

import (
	"fmt"
	"os/exec"

	"example.com/requtil"
	"github.com/gin-gonic/gin"
)

func main() {
	r := gin.Default()
	r.GET("/ping", func(c *gin.Context) {
		host := requtil.ReadQuery(c, "host") // source is INSIDE the dep
		out, _ := exec.Command("sh", "-c", fmt.Sprintf("ping -c1 %s", host)).Output()
		c.String(200, string(out))
	})
	_ = r.Run(":8080")
}
