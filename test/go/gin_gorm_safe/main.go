// Gin + Gorm handlers that read untrusted input but use it safely — a
// false-positive control. The analyzer must stay silent here.
package main

import (
	"github.com/gin-gonic/gin"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

var db *gorm.DB

func main() {
	db, _ = gorm.Open(mysql.Open("user:pass@/dbname"), &gorm.Config{})

	r := gin.Default()

	// Safe: parameterized Gorm queries. The tainted value is a bound "?"
	// placeholder, never spliced into the SQL text (Raw/Where logical arg 0).
	r.GET("/user", func(c *gin.Context) {
		id := c.Query("id")
		var u map[string]any
		db.Raw("SELECT * FROM users WHERE id = ?", id).Scan(&u)
		db.Where("id = ?", id).First(&u)
		c.JSON(200, u)
	})

	// Safe: primary-key lookup (First's condition is a bound argument), and the
	// input is only echoed back as JSON, which is not an injection sink.
	r.GET("/user/:id", func(c *gin.Context) {
		id := c.Param("id")
		var u map[string]any
		db.First(&u, id)
		c.JSON(200, gin.H{"echo": id})
	})

	_ = r.Run(":8080")
}
