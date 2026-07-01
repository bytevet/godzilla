package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"

	_ "github.com/mattn/go-sqlite3"
)

var db *sql.DB

func init() {
	db, _ = sql.Open("sqlite3", ":memory:")
}

func handler2(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	rows, err := db.Query("SELECT name FROM users WHERE id = ?", id)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer rows.Close()
	var name string
	for rows.Next() {
		rows.Scan(&name)
		fmt.Fprintf(w, "User: %s", name)
	}
}

type User struct {
	ID   string
	Name string
}

func (u *User) GetByID() error {
	query := fmt.Sprintf("SELECT name FROM users WHERE id = '%s'", u.ID)
	return db.QueryRow(query).Scan(&u.Name)
}

func handler3(w http.ResponseWriter, r *http.Request) {
	idStr := r.URL.Query().Get("id")
	user := &User{ID: idStr}
	if err := user.GetByID(); err != nil {
		http.Error(w, "User not found", 404)
		return
	}

	if err := json.NewEncoder(w).Encode(user); err != nil {
		http.Error(w, "Failed to encode user", 500)
		return
	}
}

func main() {
	http.HandleFunc("/user", func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		// Vulnerable: Direct string concatenation in SQL query
		query := fmt.Sprintf("SELECT name FROM users WHERE id = '%s'", id)
		rows, err := db.Query(query)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		defer rows.Close()
		var name string
		for rows.Next() {
			rows.Scan(&name)
			fmt.Fprintf(w, "User: %s", name)
		}
	})

	http.HandleFunc("/user/v2", handler2)
	http.HandleFunc("/user/v3", handler3)

	http.ListenAndServe(":8080", nil)
}
