package reporter

import (
	"sync"

	"github.com/leaktk/gcs-filter/scanner"
)

func wgReport(wg *sync.WaitGroup, r Reporter, leaks []*scanner.Leak) {
	r.Report(leaks)
	wg.Done()
}

// MultiReporter provides a way to send to multiple reporters at once
type MultiReporter struct {
	reporters []Reporter
}

// NewMultiReporter provides a configured MultiReporter
func NewMultiReporter(reporters []Reporter) (*MultiReporter, error) {
	return &MultiReporter{reporters: reporters}, nil
}

// Report forwards leaks to the reporters
func (r *MultiReporter) Report(leaks []*scanner.Leak) {
	var wg sync.WaitGroup

	for _, r := range r.reporters {
		wg.Add(1)
		go wgReport(&wg, r, leaks)
	}

	wg.Wait()
}

// Close runs close on the reporters and returns the first error it encounters
// but still runs close on all of them
func (r *MultiReporter) Close() error {
	var err error

	for _, r := range r.reporters {
		if closeErr := r.Close(); closeErr != nil {
			err = closeErr
		}
	}

	return err
}
