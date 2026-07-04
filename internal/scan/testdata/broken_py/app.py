# Deliberately un-parseable Python: the frontend must FAIL to convert this,
# and Scan must record python as detected-but-not-converted (coverage failure)
# rather than silently reporting a clean result. Used by the fail-closed tests
# for WS3 (internal/scan/scan_test.go, cmd/godzilla/main_test.go).
def handler(:
    return
