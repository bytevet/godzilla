module godzilla/test/go/unknown_framework_safe

go 1.25.5

require example.com/miniweb v0.0.0

replace example.com/miniweb => ../unknown_framework/miniweb
