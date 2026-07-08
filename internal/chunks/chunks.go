// Package chunks runs an index range in contiguous chunks across workers.
package chunks

import (
	"runtime"
	"sync"
)

// Run splits [0,n) into up to GOMAXPROCS contiguous chunks and calls fn(start,
// end) for each on its own goroutine, waiting for all to finish. fn must write
// only to index-aligned slots so results stay deterministic.
func Run(n int, fn func(start, end int)) {
	workers := runtime.GOMAXPROCS(0)
	if workers > n {
		workers = n
	}
	if workers < 1 {
		workers = 1
	}
	size := (n + workers - 1) / workers
	var wg sync.WaitGroup
	for start := 0; start < n; start += size {
		end := start + size
		if end > n {
			end = n
		}
		wg.Add(1)
		go func(start, end int) { defer wg.Done(); fn(start, end) }(start, end)
	}
	wg.Wait()
}
