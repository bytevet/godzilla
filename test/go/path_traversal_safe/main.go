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
		// Safe: filepath.Base strips any directory component (including "../"
		// traversal sequences), so the value handed to os.Open can never
		// escape the intended directory - this must produce ZERO findings.
		safeName := filepath.Base(filename)
		f, err := os.Open(safeName)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		defer f.Close()
		io.Copy(w, f)
	})
	fmt.Println("Server starting on :8086")
	http.ListenAndServe(":8086", nil)
}
