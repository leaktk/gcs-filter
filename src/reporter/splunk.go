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
func (r *SplunkReporter) Report(leak *scanner.Leak) {
	endTimer := perf.Timer("ReportToSplunk")
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
		return
	}

	req, err := http.NewRequest("POST", r.config.Collector, bytes.NewReader(body))
	if err != nil {
		logging.Error("http.Request: %w", err)
		return
	}

	req.Header.Add("Authorization", fmt.Sprintf("Splunk %s", r.config.Token))
	resp, err := r.client.Do(req)

	if err != nil {
		logging.Error("r.client.Do: %s", err.Error())
		return
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		logging.Error("io.ReadAll(resp.Body): %w", err)
		return
	}

	if resp.StatusCode >= 400 {
		logging.Error("splunk response: status_code=%d resp=\"%s\"", resp.StatusCode, string(respBody))
	} else {
		logging.Info("splunk response: status_code=%d resp=\"%s\"", resp.StatusCode, string(respBody))
	}
	endTimer()
}

// Close closes any idle connections
func (r *SplunkReporter) Close() error {
	r.client.CloseIdleConnections()
	return nil
}
