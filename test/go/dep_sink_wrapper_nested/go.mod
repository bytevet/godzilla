module godzilla/test/go/dep_sink_wrapper_nested

go 1.25.5

require example.com/svc v0.0.0

require example.com/cmdutil v0.0.0 // indirect

replace example.com/svc => ./svc

replace example.com/cmdutil => ./cmdutil
