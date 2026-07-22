// Echo command injection. The route handler's echo.Context is seeded as a
// request object (collectRouteHandlers recognizes the e.GET registration; the
// named echo.HandlerFunc arg is unwrapped via ChangeType), so request taint
// flows through the LOWERED echo body of c.QueryParam into the shell sink WITHOUT
// any echo-specific source glob — request-object provenance covers it. This is
// the regression guard for retiring the echo accessor globs.
package main

import (
	"os/exec"

	"github.com/labstack/echo/v4"
)

func main() {
	e := echo.New()
	e.GET("/run", func(c echo.Context) error {
		host := c.QueryParam("host")                // request accessor (lowered body)
		return exec.Command("sh", "-c", host).Run() // command injection (sink)
	})
	e.Logger.Fatal(e.Start(":8080"))
}
