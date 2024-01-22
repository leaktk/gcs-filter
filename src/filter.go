package filter

import (
	"context"
	"fmt"
	"os"

	"cloud.google.com/go/storage"
	"github.com/GoogleCloudPlatform/functions-framework-go/functions"
	"github.com/cloudevents/sdk-go/v2/event"
	"github.com/googleapis/google-cloudevents-go/cloud/storagedata"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/leaktk/gcs-filter/config"
	"github.com/leaktk/gcs-filter/logging"
	"github.com/leaktk/gcs-filter/perf"
	"github.com/leaktk/gcs-filter/reporter"
	"github.com/leaktk/gcs-filter/scanner"
)

const removalNotice = "This file contained potentially sensitive information and has been removed."

var rptr reporter.Reporter
var storageClient *storage.Client

// Feature flags - see the init section below for what they're set to
var allowRemoveObjectContent bool

func init() {
	// Set feature flags
	// allowRemoveObjectContent (default: true) - a flag for enabling or disabling removing content
	allowRemoveObjectContent = os.Getenv("LEAKTK_GCS_FILTER_ALLOW_REMOVE") != "false"

	// Setup the reporter
	ctx := context.Background()

	reporterConfig, err := config.NewReporterConfig()
	if err != nil {
		logging.Error("config.NewReporterConfig: %w", err)
	} else {
		rptr, err = reporter.NewReporter(ctx, &reporterConfig)

		if err != nil {
			logging.Fatal("reporter.NewReporter: %w", err)
		}
	}

	// Setup the storage client
	storageClient, err = storage.NewClient(ctx)
	if err != nil {
		logging.Fatal("storage.NewClient: %w", err)
	}

	// Register the entrypoint
	functions.CloudEvent("AnalyzeObject", analyzeObject)
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
	if config.PathExcluded(objectName) {
		logging.Info("skipping because path excluded: object_name=\"%v\"", objectName)
		return nil
	}
	endTimer()

	endTimer = perf.Timer("ScanObject")
	object := storageClient.Bucket(bucketName).Object(objectName)
	leaks, err := scanner.Scan(ctx, bucketName, objectName, object)
	if err != nil {
		logging.Error("scanner.Scan: %w", err)
	}

	logging.Info("scan details: leak_count=%d object_name=\"%v\"", len(leaks), objectName)

	// The iteration is backwards so that the leaks are reported in the right
	// order via defer.
	removeObjectContent := false
	for i := len(leaks) - 1; i >= 0; i-- {
		leak := &leaks[i]

		// Defer is used so that we don't have to iterate through the leaks again
		// at the end or handle getting to the end in different error cases
		// first.
		defer rptr.Report(leak)

		if !removeObjectContent && leak.IsProductionSecretRule() {
			removeObjectContent = true
		}
	}
	endTimer()

	if allowRemoveObjectContent && removeObjectContent {
		endTimer = perf.Timer("RemoveObjectContent")
		logging.Info("removing object content: object_name=\"%v\"", objectName)

		objectWriter := object.NewWriter(ctx)
		objectWriter.ContentType = "text/plain"
		// Close not deferred because we want to know if it errors out after
		// a successful write

		_, err = objectWriter.Write([]byte(removalNotice))
		if err != nil {
			objectWriter.Close()
			return fmt.Errorf("objectWriter.Write: %w", err)
		}

		err = objectWriter.Close()
		if err != nil {
			return fmt.Errorf("objectWriter.Close: %w", err)
		}

		logging.Info("object content removed: object_name=\"%v\"", objectName)
		endTimer()
	}

	return nil
}
