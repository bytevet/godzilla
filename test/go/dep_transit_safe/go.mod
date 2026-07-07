module godzilla/test/go/dep_transit_safe

go 1.25.5

require example.com/util v0.0.0

replace example.com/util => ../dep_transit/util
