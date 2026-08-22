## What and why

<!-- One or two sentences. Link the issue if there is one. -->

## Checks

- [ ] `go build ./... && go test ./...` pass
- [ ] `gofmt -l cmd converters internal rulepacks test/corpus` is empty
- [ ] A new or changed rule ships with a `test/<lang>/<case>/` sample and its `expected.yaml`
- [ ] A behaviour change has a regression test

<!-- Changing the guard/rule contract (rule fields, `when:` facts, `#idx` pinning) or
     proto/*.proto needs maintainer agreement first — link that discussion here. -->
