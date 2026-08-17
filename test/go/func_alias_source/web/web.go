package web

import "funcaliassource/macaron"

// The shape that hid grafana CVE-2021-43798: re-exporting a function as a
// package-level VARIABLE, which makes every call through it an indirect call.
var Params = macaron.Params
