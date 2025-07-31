package reporter

import (
	"context"

	"cloud.google.com/go/bigquery"

	"github.com/leaktk/gcs-filter/config"
	"github.com/leaktk/gcs-filter/logging"
	"github.com/leaktk/gcs-filter/perf"
	"github.com/leaktk/gcs-filter/scanner"
)

// BigQueryReporter stores results in BigQuery for further analysis
type BigQueryReporter struct {
	client   *bigquery.Client
	ctx      context.Context
	inserter *bigquery.Inserter
}

// NewBigQueryReporter returns a configured BigQueryReporter
func NewBigQueryReporter(ctx context.Context, rc *config.Reporter) (*BigQueryReporter, error) {
	client, err := bigquery.NewClient(ctx, rc.BigQuery.ProjectID)

	if err != nil {
		return nil, err
	}

	return &BigQueryReporter{
		client:   client,
		ctx:      ctx,
		inserter: client.Dataset(rc.BigQuery.DatasetID).Table(rc.BigQuery.TableID).Inserter(),
	}, nil
}

// Report save the leak details in BigQuery
func (r *BigQueryReporter) Report(leaks []*scanner.Leak) {
	endTimer := perf.Timer("ReportToBigQuery")
	if err := r.inserter.Put(r.ctx, leaks); err != nil {
		logging.Error("BigQuery insert failed: %w", err)
	}
	endTimer()
}

// Close cleans up the big query client connection
func (r *BigQueryReporter) Close() error {
	return r.client.Close()
}
