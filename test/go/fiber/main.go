package main

import (
	"os/exec"

	"github.com/gofiber/fiber/v2"
)

// Fiber's *fiber.Ctx.Query is an untrusted source; the value flows into an
// os/exec command. Exercises the fiber Ctx accessor source rules. Fiber handlers
// take a context (not http.ResponseWriter/*http.Request), so this relies on the
// rule-pack accessor glob, not the frontend request-object synthesis.
func main() {
	app := fiber.New()
	app.Get("/run", func(c *fiber.Ctx) error {
		cmd := c.Query("cmd")               // fiber source
		exec.Command("sh", "-c", cmd).Run() // command injection
		return nil
	})
	app.Listen(":8080")
}
