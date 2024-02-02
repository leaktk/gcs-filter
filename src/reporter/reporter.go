package reporter

import (
	"context"
	"fmt"
	"io"

	"github.com/leaktk/gcs-filter/config"
	"github.com/leaktk/gcs-filter/logging"
	"github.com/leaktk/gcs-filter/scanner"
)

// Reporter provides an interface that other reporters can implement
type Reporter interface {
	Report(leaks []*scanner.Leak)
	io.Closer
}

func reporterFromKind(ctx context.Context, kind string, rc *config.Reporter) (Reporter, error) {
	switch kind {
	case "Logger":
		return NewLoggerReporter(ctx, rc)
	case "Splunk":
		return NewSplunkReporter(ctx, rc)
	case "BigQuery":
		return NewBigQueryReporter(ctx, rc)
	default:
		return nil, fmt.Errorf("unsuported reporter: kind=\"%v\"", kind)
	}
}

// NewReporter provides a concrete reporter struct based on the kind set in
// the config
func NewReporter(ctx context.Context, rc *config.Reporter) (Reporter, error) {
	if len(rc.Kinds) == 1 {
		return reporterFromKind(ctx, rc.Kinds[0], rc)
	}

	var reporters []Reporter

	for _, kind := range rc.Kinds {
		rptr, err := reporterFromKind(ctx, kind, rc)

		if err != nil {
			logging.Error("skipping reporter: kind=\"%s\" err=%w", kind, err)
		} else {
			reporters = append(reporters, rptr)
		}
	}

	return NewMultiReporter(reporters)
}
