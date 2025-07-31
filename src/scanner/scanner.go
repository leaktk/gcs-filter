package scanner

import (
	"context"
	"crypto/md5" // #nosec G501
	"fmt"
	"time"

	"cloud.google.com/go/storage"

	gitleaksconfig "github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/detect"
	"github.com/zricethezav/gitleaks/v8/sources"

	"github.com/leaktk/gcs-filter/logging"
)

const maxArchiveDepth = 8
const maxDecodeDepth = 8

func leakURL(bucketName, objectName string, lineNumber int) string {
	return fmt.Sprintf("gs://%v/%v#L%d", bucketName, objectName, lineNumber)
}

func leakID(leakURL, offender string) string {
	return fmt.Sprintf("%x", md5.Sum([]byte(leakURL+offender))) // #nosec G401
}

func now() string {
	return time.Now().UTC().Format(time.RFC3339)
}

func shouldSkipPath(cfg *gitleaksconfig.Config, path string) bool {
	for _, a := range cfg.Allowlists {
		if a.PathAllowed(path) {
			return true
		}
	}

	return false
}

// Scan implements a subset of a no git scan to handle an object passed in
// Source: https://github.com/leaktk/gitleaks7/blob/main/scan/nogit.go
func Scan(ctx context.Context, cfg *gitleaksconfig.Config, bucketName, objectName string, object *storage.ObjectHandle) ([]*Leak, error) {
	var leaks []*Leak

	if shouldSkipPath(cfg, objectName) {
		logging.Info("skipping because path allowed: object_name=%q", objectName)
		return leaks, nil
	}

	objectReader, err := object.NewReader(ctx)
	if err != nil {
		return leaks, fmt.Errorf("object.NewReader: %w", err)
	}

	defer func() {
		_ = objectReader.Close()
	}()

	detector := detect.NewDetector(*cfg)
	detector.MaxArchiveDepth = maxArchiveDepth
	detector.MaxDecodeDepth = maxDecodeDepth

	file := &sources.File{
		Config:          cfg,
		Content:         objectReader,
		MaxArchiveDepth: maxArchiveDepth,
		Path:            objectName,
	}

	findings, err := detector.DetectSource(ctx, file)
	for _, finding := range findings {
		url := leakURL(bucketName, objectName, finding.StartLine)
		leaks = append(leaks, &Leak{
			ID:   leakID(url, finding.Secret),
			Type: "GoogleCloudStorageLeak",
			Data: leakData{
				AddedDate:       now(),
				DataClasses:     finding.Tags,
				FilePath:        objectName,
				LeakURL:         url,
				Line:            finding.Line,
				LineNumber:      finding.StartLine,
				Offender:        finding.Secret,
				OffenderEntropy: float64(finding.Entropy),
				Rule:            finding.Description,
			},
		})
	}

	return leaks, err
}
