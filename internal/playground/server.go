package playground

import (
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

//go:embed ui
var uiFS embed.FS

// maxMatchBody caps a /api/match body, which carries only a file id and a glob.
const maxMatchBody = 64 << 10

// Everything the page needs is served from here, so both source directives stay
// 'self'. style-src-attr is the one exception — app.js sets padding-left and
// transform as element style attributes on tree/gIR rows — and it is the same
// exception internal/report's template makes for its summary bars.
const csp = "default-src 'none'; script-src 'self'; style-src 'self' https://fonts.googleapis.com; " +
	"style-src-attr 'unsafe-inline'; font-src https://fonts.gstatic.com; connect-src 'self'; " +
	"img-src data:; base-uri 'none'; form-action 'none'; object-src 'none'"

// Handler returns the routed mux, so a test can drive the API with httptest
// instead of a listener.
func (idx *Index) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /{$}", asset("ui/index.html", "text/html; charset=utf-8"))
	mux.Handle("GET /app.js", asset("ui/app.js", "application/javascript"))
	mux.Handle("GET /base.css", asset("ui/base.css", "text/css"))
	mux.HandleFunc("GET /api/tree", idx.serveTree)
	mux.HandleFunc("GET /api/file", idx.serveFile)
	mux.HandleFunc("POST /api/match", idx.serveMatch)
	return harden(mux)
}

// harden sets the response headers and rejects a non-loopback Host. That check
// is a DNS-rebinding guard: this server hands out the machine's own source, and
// a name resolved to 127.0.0.1 would otherwise let any page the user visits read
// it cross-origin.
func harden(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", csp)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-store")
		if !loopbackHost(r.Host) {
			http.Error(w, "forbidden: the playground serves loopback hosts only", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func loopbackHost(host string) bool {
	h := host
	if hostOnly, _, err := net.SplitHostPort(host); err == nil {
		h = hostOnly
	}
	h = strings.TrimSuffix(strings.TrimPrefix(h, "["), "]")
	if h == "localhost" {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

func asset(name, contentType string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := uiFS.ReadFile(name)
		if err != nil {
			http.Error(w, "asset not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", contentType)
		_, _ = w.Write(body)
	})
}

type treeResponse struct {
	Root    string       `json:"root"`
	Version string       `json:"version"`
	Files   []*fileEntry `json:"files"`
	Presets presetView   `json:"presets"`
}

type apiError struct {
	Error string `json:"error"`
}

func (idx *Index) serveTree(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, treeResponse{
		Root:    idx.root,
		Version: idx.version,
		Files:   idx.Files(),
		Presets: idx.presets,
	})
}

func (idx *Index) serveFile(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("p")
	view := idx.View(id)
	if view == nil {
		// The requested id is not echoed: it is attacker-controlled, and a 404
		// that quotes it back reflects input into a response for no benefit.
		writeJSON(w, http.StatusNotFound, apiError{Error: "unknown file"})
		return
	}
	writeJSON(w, http.StatusOK, view)
}

func (idx *Index) serveMatch(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxMatchBody)
	var req matchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, apiError{Error: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, idx.Match(req.File, req.Pattern))
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// Serve listens on addr, announces the URL on w, optionally opens a browser, and
// blocks until the server stops.
func Serve(idx *Index, addr string, openBrowser bool, w io.Writer) error {
	// Listening first is what makes an ephemeral port (":0") usable: the URL
	// printed below is the resolved one, not the requested one.
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	url := "http://" + displayAddr(ln.Addr()) + "/"
	fmt.Fprintf(w, "gIR Playground: %s\n", url)
	if openBrowser {
		_ = openURL(url)
	}
	srv := &http.Server{
		Handler:           idx.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	return srv.Serve(ln)
}

// displayAddr renders a listener address as a host:port a browser can open: a
// wildcard bind reports 0.0.0.0/::, which is not a destination.
func displayAddr(a net.Addr) string {
	tcp, ok := a.(*net.TCPAddr)
	if !ok {
		return a.String()
	}
	host := "127.0.0.1"
	if len(tcp.IP) > 0 && !tcp.IP.IsUnspecified() {
		host = tcp.IP.String()
	}
	return net.JoinHostPort(host, strconv.Itoa(tcp.Port))
}
