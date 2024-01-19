package perf

import (
	"time"

	"github.com/leaktk/gcs-filter/logging"
)

// Timer starts a timer and returns a function to end it and log the results.
// "name" should be formatted LikeAClassName
func Timer(name string) func() {
	start := time.Now()

	return func() {
		logging.Info("%sTimer: duration=%v", name, time.Since(start))
	}
}
