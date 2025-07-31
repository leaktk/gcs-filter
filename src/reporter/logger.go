package reporter

import (
	"context"
	"encoding/json"

	"github.com/leaktk/gcs-filter/config"
	"github.com/leaktk/gcs-filter/logging"
	"github.com/leaktk/gcs-filter/perf"
	"github.com/leaktk/gcs-filter/scanner"
)

// LoggerReporter reports leaks via the logger instead of another serivce
type LoggerReporter struct {
}

// NewLoggerReporter returns a configured LoggerReporter
func NewLoggerReporter(_ context.Context, rc *config.Reporter) (*LoggerReporter, error) {
	return &LoggerReporter{}, nil
}

// Report forwards the leak details
func (r *LoggerReporter) Report(leaks []*scanner.Leak) {
	endTimer := perf.Timer("ReportToLogger")

	for _, leak := range leaks {
		data, err := json.Marshal(leak)

		if err != nil {
			logging.Error("could not marshal leak result")
			logging.Info("%v", leak)
		} else {
			logging.Info(string(data))
		}
	}

	endTimer()
}

// Close is only needed to implment the interface here
func (r *LoggerReporter) Close() error {
	return nil
}
