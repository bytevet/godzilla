package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
)

func main() {
	http.HandleFunc("/read", func(w http.ResponseWriter, r *http.Request) {
		filename := r.URL.Query().Get("file")
		// Vulnerable: Path traversal
		path := filepath.Join("/data/files", filename)
		f, err := os.Open(path)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		defer f.Close()
		io.Copy(w, f)
	})
	fmt.Println("Server starting on :8081")
	http.ListenAndServe(":8081", nil)
}
