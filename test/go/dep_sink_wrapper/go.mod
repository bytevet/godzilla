module godzilla/test/go/dep_sink_wrapper

go 1.25.5

require example.com/cmdutil v0.0.0

replace example.com/cmdutil => ./cmdutil
