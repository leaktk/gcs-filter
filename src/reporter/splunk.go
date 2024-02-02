package reporter

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/leaktk/gcs-filter/config"
	"github.com/leaktk/gcs-filter/logging"
	"github.com/leaktk/gcs-filter/perf"
	"github.com/leaktk/gcs-filter/scanner"
)

type splunkPayload struct {
	Host       string        `json:"host"`
	Index      string        `json:"index"`
	Source     string        `json:"source"`
	Event      *scanner.Leak `json:"event"`
	Sourcetype string        `json:"sourcetype"`
}

// SplunkReporter implements a reporter that forwards leaks to Splunk
type SplunkReporter struct {
	config *config.Splunk
	client http.Client
}

// NewSplunkReporter provides a configured SplunkReporter
func NewSplunkReporter(_ context.Context, rc *config.Reporter) (*SplunkReporter, error) {
	return &SplunkReporter{
		config: rc.Splunk,
		client: http.Client{
			Timeout: 60 * time.Second,
		},
	}, nil
}

// Report forwards leaks to Splunk
func (r *SplunkReporter) Report(leaks []*scanner.Leak) {
	endTimer := perf.Timer("ReportToSplunk")

	// Batch the uploads to reduce the risk of sending a really large payload
	// to Splunk, but also send multiple events at one time to reduce the delay.
	batchSize := 32

	for start := 0; start < len(leaks); start += batchSize {
		var events bytes.Buffer

		for i := start; i < len(leaks) && i-start < batchSize; i++ {
			leak := leaks[i]

			payload := splunkPayload{
				Host:       r.config.Host,
				Index:      r.config.Index,
				Source:     r.config.Source,
				Sourcetype: r.config.Sourcetype,
				Event:      leak,
			}

			body, err := json.Marshal(payload)
			if err != nil {
				logging.Error("json.Marshal: %w", err)
				continue
			}

			events.Write(body)
			events.WriteString("\n")
		}

		req, err := http.NewRequest("POST", r.config.Collector, bytes.NewReader(events.Bytes()))
		if err != nil {
			logging.Error("http.Request: %w", err)
			continue
		}

		req.Header.Add("Authorization", fmt.Sprintf("Splunk %s", r.config.Token))
		resp, err := r.client.Do(req)

		if err != nil {
			logging.Error("r.client.Do: %s", err.Error())
			continue
		}
		defer resp.Body.Close()

		respBody, err := io.ReadAll(resp.Body)
		if err != nil {
			logging.Error("io.ReadAll(resp.Body): %w", err)
			continue
		}

		if resp.StatusCode >= 400 {
			logging.Error("splunk response: status_code=%d resp=\"%s\"", resp.StatusCode, string(respBody))
		} else {
			logging.Info("splunk response: status_code=%d resp=\"%s\"", resp.StatusCode, string(respBody))
		}
	}

	endTimer()
}

// Close closes any idle connections
func (r *SplunkReporter) Close() error {
	r.client.CloseIdleConnections()
	return nil
}
