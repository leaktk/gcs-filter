package scanner

import (
	"bufio"
	"context"
	"crypto/md5"
	"fmt"
	"path/filepath"
	"time"

	"cloud.google.com/go/storage"

	gitleaksconfig "github.com/leaktk/gitleaks7/v2/config"
)

const defaultLineNumber = 1
const bufSize = 256 * 1024

func leakURL(bucketName, objectName string, lineNumber int) string {
	return fmt.Sprintf("gs://%v/%v#L%d", bucketName, objectName, lineNumber)
}

func leakID(leakURL, offender string) string {
	return fmt.Sprintf("%x", md5.Sum([]byte(leakURL+offender)))
}

func now() string {
	return time.Now().UTC().Format(time.RFC3339)
}

// Scan implements a subset of a no git scan to handle an object passed in
// Source: https://github.com/leaktk/gitleaks7/blob/main/scan/nogit.go
func Scan(ctx context.Context, cfg *gitleaksconfig.Config, bucketName, objectName string, object *storage.ObjectHandle) ([]Leak, error) {
	var leaks []Leak

	if cfg.Allowlist.PathAllowed(objectName) {
		logging.Info("skipping because path allowed: object_name=\"%v\"", objectName)
		return leaks, nil
	}

	for _, rule := range cfg.Rules {
		if rule.HasFileOrPathLeakOnly(objectName) {
			url := leakURL(bucketName, objectName, defaultLineNumber)
			offenderString := "object name offender: " + objectName

			leak := Leak{
				ID:   leakID(url, offenderString),
				Type: "GoogleCloudStorageLeak",
				Data: leakData{
					AddedDate:       now(),
					DataClasses:     rule.Tags,
					FilePath:        objectName,
					LeakURL:         leakURL(bucketName, objectName, defaultLineNumber),
					Line:            "",
					LineNumber:      defaultLineNumber,
					Offender:        offenderString,
					OffenderEntropy: -1,
					Rule:            rule.Description,
				},
			}

			leaks = append(leaks, leak)
		}
	}

	objectReader, err := object.NewReader(ctx)

	if err != nil {
		return leaks, fmt.Errorf("object.NewReader: %w", err)
	}

	defer objectReader.Close()
	scanner := bufio.NewScanner(objectReader)
	scanner.Buffer(make([]byte, bufSize), bufSize)

	for lineNumber := 1; scanner.Scan(); lineNumber++ {
		line := scanner.Text()

		for _, rule := range cfg.Rules {
			if rule.AllowList.FileAllowed(filepath.Base(objectName)) ||
				rule.AllowList.PathAllowed(objectName) {
				continue
			}

			offender := rule.Inspect(line)
			if offender.IsEmpty() {
				continue
			}

			if cfg.Allowlist.RegexAllowed(line) {
				continue
			}

			if rule.File.String() != "" && !rule.HasFileLeak(filepath.Base(objectName)) {
				continue
			}

			if rule.Path.String() != "" && !rule.HasFilePathLeak(objectName) {
				continue
			}

			url := leakURL(bucketName, objectName, lineNumber)
			offenderString := offender.ToString()

			leak := Leak{
				ID:   leakID(url, offenderString),
				Type: "GoogleCloudStorageLeak",
				Data: leakData{
					AddedDate:       now(),
					DataClasses:     rule.Tags,
					FilePath:        objectName,
					LeakURL:         leakURL(bucketName, objectName, lineNumber),
					Line:            line,
					LineNumber:      lineNumber,
					Offender:        offenderString,
					OffenderEntropy: offender.EntropyLevel,
					Rule:            rule.Description,
				},
			}

			leaks = append(leaks, leak)
		}
	}

	return leaks, scanner.Err()
}
