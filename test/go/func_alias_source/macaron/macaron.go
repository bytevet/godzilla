package macaron

import "net/http"

// Stands in for macaron's route-param accessor: a free function taking the
// request, which grafana and gogs both reach through a re-exporting variable.
func Params(r *http.Request) map[string]string { return map[string]string{} }
