package perf

import (
	"time"

	"github.com/leaktk/gcs-filter/logging"
)

// Timer starts a timer and returns a function to end it and log the results.
// "name" should be formatted LikeAClassName
func Timer(name string) func() {
	start := time.Now()
	logging.Info("%sTimer: start=%d", name, start.Unix())

	return func() {
		end := time.Now()
		logging.Info("%sTimer: end=%d duration=%v", name, end.Unix(), end.Sub(start))
	}
}
