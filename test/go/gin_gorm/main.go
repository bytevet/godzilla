// Gin + Gorm handlers with SQL injection and command injection.
//
// Untrusted input is read via Gin's request accessors (c.Query / c.Param) and
// formatted directly into a Gorm raw query / WHERE condition (SQLi) and a shell
// command (command injection), with no parameterization.
package main

import (
	"fmt"
	"os/exec"

	"github.com/gin-gonic/gin"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

var db *gorm.DB

func main() {
	db, _ = gorm.Open(mysql.Open("user:pass@/dbname"), &gorm.Config{})

	r := gin.Default()

	// SQLi: a Gin query parameter formatted into a Gorm raw query.
	r.GET("/user", func(c *gin.Context) {
		id := c.Query("id")
		var name string
		db.Raw(fmt.Sprintf("SELECT name FROM users WHERE id = '%s'", id)).Scan(&name)
		c.JSON(200, gin.H{"name": name})
	})

	// SQLi: a Gin path parameter formatted into a Gorm WHERE condition.
	r.GET("/user/:id", func(c *gin.Context) {
		id := c.Param("id")
		var u map[string]any
		db.Where(fmt.Sprintf("id = '%s'", id)).First(&u)
		c.JSON(200, u)
	})

	// Command injection: a Gin query parameter formatted into a shell command.
	r.GET("/ping", func(c *gin.Context) {
		host := c.Query("host")
		out, _ := exec.Command("sh", "-c", fmt.Sprintf("ping -c1 %s", host)).Output()
		c.String(200, string(out))
	})

	_ = r.Run(":8080")
}
