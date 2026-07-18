// Package web mimics a router's route-parameter accessor as a free function —
// the shape used by macaron and Grafana's pkg/web (web.Params(req)). It returns
// untrusted path/query parameters captured from the request URL.
package web

import "net/http"

func Params(r *http.Request) map[string]string {
	return map[string]string{}
}
