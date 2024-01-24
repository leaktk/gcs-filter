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

func pathExcluded(filePath string) bool {
	for _, re := range cfg.ExcludeList {
		if re.MatchString(filePath) {
			return true
		}
	}

	return false
}

func analyzeObject(ctx context.Context, e event.Event) error {
	defer perf.Timer("AnalyzeObject")()
	var data storagedata.StorageObjectData

	endTimer := perf.Timer("UnmarshalAndExcludeByPath")
	if err := protojson.Unmarshal(e.Data(), &data); err != nil {
		return fmt.Errorf("protojson.Unmarshal: %w", err)
	}

	bucketName := data.GetBucket()
	if bucketName == "" {
		return fmt.Errorf("empty object bucket")
	}

	objectName := data.GetName()
	if objectName == "" {
		return fmt.Errorf("empty object name")
	}

	logging.Info("starting analysis: object_name=\"%v\"", objectName)
	if pathExcluded(objectName) {
		logging.Info("skipping because path excluded: object_name=\"%v\"", objectName)
		return nil
	}
	endTimer()

	endTimer = perf.Timer("ScanObject")
	object := storageClient.Bucket(bucketName).Object(objectName)
	leaks, err := scanner.Scan(ctx, cfg.Gitleaks, bucketName, objectName, object)
	if err != nil {
		logging.Error("scanner.Scan: %w", err)
	}

	logging.Info("scan details: leak_count=%d object_name=\"%v\"", len(leaks), objectName)

	// The iteration is backwards so that the leaks are reported in the right
	// order via defer.
	leakFound := false
	for i := len(leaks) - 1; i >= 0; i-- {
		leak := &leaks[i]

		// Defer is used so that we don't have to iterate through the leaks again
		// at the end or handle getting to the end in different error cases
		// first.
		defer leakReporter.Report(leak)

		if !leakFound && leak.IsProductionSecretRule() {
			leakFound = true
		}
	}
	endTimer()

	if leakRedactor.Enabled && leakFound {
		leakRedactor.Redact(ctx, objectName, object)
	}

	return nil
}
