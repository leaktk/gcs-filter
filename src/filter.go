package filter

import (
	"context"
	"fmt"

	"cloud.google.com/go/storage"
	"github.com/GoogleCloudPlatform/functions-framework-go/functions"
	"github.com/cloudevents/sdk-go/v2/event"
	"github.com/googleapis/google-cloudevents-go/cloud/storagedata"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/leaktk/gcs-filter/config"
	"github.com/leaktk/gcs-filter/logging"
	"github.com/leaktk/gcs-filter/perf"
	"github.com/leaktk/gcs-filter/redactor"
	"github.com/leaktk/gcs-filter/reporter"
	"github.com/leaktk/gcs-filter/scanner"
)

var leakReporter reporter.Reporter
var storageClient *storage.Client
var leakRedactor *redactor.Redactor
var cfg *config.Config

func init() {
	var err error

	// Load the config
	cfg, err = config.NewConfig()
	if err != nil {
		logging.Fatal("config.NewConfig: %s", err.Error())
	}

	// Create a context for services to use
	ctx := context.Background()

	// Setup the reporter
	leakReporter, err = reporter.NewReporter(ctx, cfg.Reporter)
	if err != nil {
		logging.Fatal("reporter.NewReporter: %w", err)
	}

	// Setup the storage client
	storageClient, err = storage.NewClient(ctx)
	if err != nil {
		logging.Fatal("storage.NewClient: %w", err)
	}

	// Setup the redactor
	leakRedactor = redactor.NewRedactor(cfg.Redactor, storageClient)

	// Register the entrypoint
	functions.CloudEvent("AnalyzeObject", analyzeObject)
}

func analyzeObject(ctx context.Context, e event.Event) error {
	defer perf.Timer("AnalyzeObject")()
	var data storagedata.StorageObjectData

	endTimer := perf.Timer("Unmarshal")
	if err := protojson.Unmarshal(e.Data(), &data); err != nil {
		endTimer()
		return fmt.Errorf("protojson.Unmarshal: %w", err)
	}

	bucketName := data.GetBucket()
	if bucketName == "" {
		endTimer()
		return fmt.Errorf("empty object bucket")
	}

	objectName := data.GetName()
	if objectName == "" {
		endTimer()
		return fmt.Errorf("empty object name")
	}
	endTimer()

	endTimer = perf.Timer("ScanObject")
	logging.Info("starting analysis: object_name=\"%v\"", objectName)
	object := storageClient.Bucket(bucketName).Object(objectName)
	leaks, err := scanner.Scan(ctx, cfg.Gitleaks, bucketName, objectName, object)
	if err != nil {
		logging.Error("scanner.Scan: %w", err)
	}

	logging.Info("scan details: leak_count=%d object_name=\"%v\"", len(leaks), objectName)
	if len(leaks) == 0 {
		endTimer()
		// nothing else to do here
		return nil
	}

	defer leakReporter.Report(leaks)

	leakFound := false
	for _, leak := range leaks {
		if !leakFound && leak.IsProductionSecretRule() {
			leakFound = true
			break
		}
	}
	endTimer()

	if leakRedactor.Enabled && leakFound {
		err = leakRedactor.Redact(ctx, objectName, object)

		if err != nil {
			return err
		}
	}

	return nil
}
