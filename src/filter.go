package filter

import (
	"context"
	"errors"
	"fmt"
	"os"

	"cloud.google.com/go/profiler"
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
var unmarshaller protojson.UnmarshalOptions

func init() {
	var err error

	// Load the config
	cfg, err = config.NewConfig()
	if err != nil {
		logging.Fatal("config.NewConfig: %s", err.Error())
	}

	// setup profiler
	if v := os.Getenv("LEAKTK_GCS_FILTER_ENABLE_PROFILER"); len(v) > 0 && v != "0" {
		if err := profiler.Start(cfg.Profiler); err != nil {
			logging.Fatal("profiler.Start: %v", err)
		}
	}

	// Create a context for services to use
	ctx := context.Background()

	// Setup the reporter
	leakReporter, err = reporter.NewReporter(ctx, cfg.Reporter)
	if err != nil {
		logging.Fatal("reporter.NewReporter: %v", err)
	}

	// Setup the storage client
	storageClient, err = storage.NewClient(ctx)
	if err != nil {
		logging.Fatal("storage.NewClient: %v", err)
	}

	// Setup the redactor
	leakRedactor = redactor.NewRedactor(cfg.Redactor, storageClient)

	// Setup unmarshaller
	unmarshaller.DiscardUnknown = true
	unmarshaller.AllowPartial = true

	// Register the entrypoint
	functions.CloudEvent("AnalyzeObject", analyzeObject)
}

func analyzeObject(ctx context.Context, e event.Event) error {
	defer perf.Timer("AnalyzeObject")()
	var data storagedata.StorageObjectData

	endTimer := perf.Timer("Unmarshal")
	if err := unmarshaller.Unmarshal(e.Data(), &data); err != nil {
		endTimer()
		return fmt.Errorf("protojson.Unmarshal: %w", err)
	}

	bucketName := data.GetBucket()
	if bucketName == "" {
		endTimer()
		return errors.New("empty object bucket")
	}

	objectName := data.GetName()
	if objectName == "" {
		endTimer()
		return errors.New("empty object name")
	}
	endTimer()

	endTimer = perf.Timer("ScanObject")
	logging.Info("starting analysis: object_name=%q", objectName)
	object := storageClient.Bucket(bucketName).Object(objectName)
	leaks, err := scanner.Scan(ctx, cfg.Betterleaks, bucketName, objectName, object)
	if err != nil {
		logging.Error("scanner.Scan: %v object_name=%q", err, objectName)
	}

	if len(leaks) == 0 {
		logging.Info("scan details: leak_count=%d has_prod_secret=false object_name=%q", len(leaks), objectName)
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
	logging.Info("scan details: leak_count=%d has_prod_secret=%v object_name=%q", len(leaks), leakFound, objectName)
	endTimer()

	if leakRedactor.Enabled && leakFound {
		err = leakRedactor.Redact(ctx, objectName, object)

		if err != nil {
			logging.Error("leakRedactor.Redact: %v object_name=%q", err, objectName)
			return err
		}
	}

	return nil
}
