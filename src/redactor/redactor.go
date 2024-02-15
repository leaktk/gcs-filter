package redactor

import (
	"context"
	"errors"
	"fmt"

	"cloud.google.com/go/storage"

	"github.com/leaktk/gcs-filter/config"
	"github.com/leaktk/gcs-filter/logging"
	"github.com/leaktk/gcs-filter/perf"
)

const notice = "This file contained potentially sensitive information and has been removed.\n"

// Redactor removes objects from the bucket and optionally quarantines them
type Redactor struct {
	Enabled          bool
	quarantine       bool
	quarantineBucket *storage.BucketHandle
}

// NewRedactor returns a configured pointer to a Redactor struct
func NewRedactor(rc *config.Redactor, storageClient *storage.Client) *Redactor {
	return &Redactor{
		Enabled:          rc.Enabled,
		quarantine:       rc.Quarantine,
		quarantineBucket: storageClient.Bucket(rc.QuarantineBucketName),
	}
}

// Redact removes the content of the object if the redactor is enabled and if
// quarantine is enabled, the object is first copied to the quarantine bucket.
func (r *Redactor) Redact(ctx context.Context, objectName string, object *storage.ObjectHandle, generation int64) error {
	endTimer := perf.Timer("RedactObject")
	// Added here for safey in case the conditional in the other code is
	// removed by mistake
	if !r.Enabled {
		return errors.New("redact called when the redactor has been disabled")
	}

	if r.quarantine {
		if err := r.copyToQuarantineBucket(ctx, objectName, object, generation); err != nil {
			return err
		}
	}

	logging.Info("removing object content: object_name=\"%v\"", objectName)
	objectWriter := object.NewWriter(ctx)
	objectWriter.ContentType = "text/plain"

	// Close not deferred because we want to know if it errors out after
	// a successful write
	_, err := objectWriter.Write([]byte(notice))
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
	return nil
}

func (r *Redactor) copyToQuarantineBucket(ctx context.Context, objectName string, src *storage.ObjectHandle, generation int64) error {
	logging.Info("quarantining object: object_name=\"%v\"", objectName)

	dest := r.quarantineBucket.Object(objectName)
	// Don't write to the object if it already exists
	dest.If(storage.Conditions{DoesNotExist: true})

	if _, err := dest.CopierFrom(src.Generation(generation)).Run(ctx); err != nil {
		return fmt.Errorf("could not copy %q: %w", objectName, err)
	}

	logging.Info("object quarantined: object_name=\"%v\"", objectName)
	return nil
}
