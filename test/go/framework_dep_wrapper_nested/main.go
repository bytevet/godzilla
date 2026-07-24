package main

// NESTED dependency wrappers: user -> svc.Fetch -> requtil.ReadQuery -> c.Query.
// The source (c.Query) is two dependency layers deep, and neither middle layer is
// called directly by user code. Guards the generalized source-host seeding: any
// reachable dep that hosts a framework-accessor source is seeded, and the return
// taint is carried up the wrapper chain by caller re-enqueue.
import (
	"fmt"
	"os/exec"
	"github.com/gin-gonic/gin"
	"example.com/svc"
)
func main() {
	r := gin.Default()
	r.GET("/ping", func(c *gin.Context) {
		host := svc.Fetch(c, "host") // user -> svc -> requtil -> c.Query
		out, _ := exec.Command("sh", "-c", fmt.Sprintf("ping -c1 %s", host)).Output()
		c.String(200, string(out))
	})
	_ = r.Run(":8080")
}
