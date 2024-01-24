package config

import (
	// Used to pull in embeded files when dist is built
	_ "embed"
	"errors"
	"os"
	"strings"

	"github.com/BurntSushi/toml"
	gitleaksconfig "github.com/leaktk/gitleaks7/v2/config"
)

// Splunk contains the config for using the Splunk reporter to log leaks
type Splunk struct {
	Collector  string
	Host       string
	Index      string
	Source     string
	Sourcetype string
	Token      string
}

// BigQuery contains the config for using the BigQueryReporter to log leaks
type BigQuery struct {
	ProjectID string
	DatasetID string
	TableID   string
}

// Reporter contains the top level reporter config to pass to the various
// NewReporter functions to set up that reporter
type Reporter struct {
	Kinds    []string
	Splunk   *Splunk
	BigQuery *BigQuery
}

// Redactor contains config and feature flags around redacting content
type Redactor struct {
	Enabled              bool
	Quarantine           bool
	QuarantineBucketName string
}

// Config contains all of the config for the app
type Config struct {
	Gitleaks *gitleaksconfig.Config
	Redactor *Redactor
	Reporter *Reporter
}

//go:embed gitleaks.toml
var rawGitleaks string

func newGitleaksConfig() (*gitleaksconfig.Config, error) {
	var cfg gitleaksconfig.Config
	tomlLoader := gitleaksconfig.TomlLoader{}

	_, err := toml.Decode(rawGitleaks, &tomlLoader)

	if err != nil {
		return &cfg, err
	}

	cfg, err = tomlLoader.Parse()
	return &cfg, err
}

func newRedactorConfig() (*Redactor, error) {
	r := &Redactor{
		Enabled:              os.Getenv("LEAKTK_GCS_FILTER_REDACTOR_ENABLED") != "false",
		Quarantine:           os.Getenv("LEAKTK_GCS_FILTER_REDACTOR_QUARANTINE") == "true",
		QuarantineBucketName: os.Getenv("LEAKTK_GCS_FILTER_REDACTOR_QUARANTINE_BUCKET_NAME"),
	}

	if r.Quarantine {
		if !r.Enabled {
			return nil, errors.New("LEAKTK_GCS_FILTER_REDACTOR_ENABLED must be set to true if LEAKTK_GCS_FILTER_REDACTOR_QUARANTINE is true")
		}

		if len(r.QuarantineBucketName) == 0 {
			return nil, errors.New("LEAKTK_GCS_FILTER_REDACTOR_QUARANTINE_BUCKET_NAME must be set if LEAKTK_GCS_FILTER_REDACTOR_QUARANTINE is true")
		}
	}

	return r, nil
}

func newReporterConfig() (*Reporter, error) {
	r := &Reporter{
		Kinds: strings.Split(strings.ReplaceAll(os.Getenv("LEAKTK_GCS_FILTER_REPORTER_KINDS"), " ", ""), ","),
	}

	if len(r.Kinds) == 0 {
		return nil, errors.New("LEAKTK_GCS_FILTER_REPORTER_KINDS must not be empty")
	}

	for _, kind := range r.Kinds {
		switch kind {
		case "Splunk":
			r.Splunk = &Splunk{
				Collector:  os.Getenv("LEAKTK_GCS_FILTER_SPLUNK_REPORTER_COLLECTOR"),
				Host:       os.Getenv("LEAKTK_GCS_FILTER_SPLUNK_REPORTER_HOST"),
				Index:      os.Getenv("LEAKTK_GCS_FILTER_SPLUNK_REPORTER_INDEX"),
				Source:     os.Getenv("LEAKTK_GCS_FILTER_SPLUNK_REPORTER_SOURCE"),
				Sourcetype: os.Getenv("LEAKTK_GCS_FILTER_SPLUNK_REPORTER_SOURCETYPE"),
				Token:      os.Getenv("LEAKTK_GCS_FILTER_SPLUNK_REPORTER_TOKEN"),
			}
		case "BigQuery":
			r.BigQuery = &BigQuery{
				ProjectID: os.Getenv("LEAKTK_GCS_FILTER_BIGQUERY_REPORTER_PROJECT_ID"),
				DatasetID: os.Getenv("LEAKTK_GCS_FILTER_BIGQUERY_REPORTER_DATASET_ID"),
				TableID:   os.Getenv("LEAKTK_GCS_FILTER_BIGQUERY_REPORTER_TABLE_ID"),
			}
		}
	}

	return r, nil
}

// NewConfig loads the config for the app from memory and env vars
func NewConfig() (*Config, error) {
	gitleaksConfig, err := newGitleaksConfig()
	if err != nil {
		return nil, err
	}

	redactorConfig, err := newRedactorConfig()
	if err != nil {
		return nil, err
	}

	return &Config{
		Gitleaks: gitleaksConfig,
		Redactor: redactorConfig,
	}, nil
}
