# leaktk-gcs-filter

Filter objects containing leaks from Google Cloud Storage

## Settings

All settings mentioned in the different sections below are environment
variables and should be exported during a `make deploy`.

### Deployment

In addition to the other component env vars defined below, the following
settings need to be defined for a deployment:

- `LEAKTK_GCS_FILTER_PROJECT`: is the project the function will be deployed to

- `LEAKTK_GCS_FILTER_REGION`: is the region the function will be deployed to

- `LEAKTK_GCS_FILTER_TRIGGER_BUCKET`: is the bucket that the function will
  monitor

And these settings are optional (see the [Makefile](./Makefile) for defaults):

- `LEAKTK_GCS_FILTER_CONCURRENCY`: is how many connections a single instance
  should allow at once

- `LEAKTK_GCS_FILTER_CPU`: sets the CPU limits for the function

- `LEAKTK_GCS_FILTER_MEMORY`: sets the memory limits for the function

- `LEAKTK_GCS_FILTER_TIMEOUT`: sets runtime limits for the function

- `LEAKTK_PATTERN_SERVER_URL`: is the base url for pattern server
  (`/patterns/gitleaks/8.18.2`, will be appended to it)

- `LEAKTK_PATTERN_SERVER_CURL_FLAGS`: are curl flags for making requests to the
  pattern server

### Redaction

Only rules tagged `type:secret` and **not** `group:leaktk-testing` are in scope for
redaction. If the redactor is enabled, the full contents will be removed from
the bucket.

Redactor settings:

- `LEAKTK_GCS_FILTER_REDACTOR_ENABLED` (default: `true`): turns redaction on or
  off

- `LEAKTK_GCS_FILTER_REDACTOR_QUARANTINE` (default: `false`): turns on backing
  up files containing leaks to the the bucket defined by
  `LEAKTK_GCS_FILTER_REDACTOR_QUARANTINE_BUCKET_NAME`

Required settings if quarantine is enabled:

- `LEAKTK_GCS_FILTER_REDACTOR_QUARANTINE_BUCKET_NAME`: This defines the bucket
  that files will be copied to if `LEAKTK_GCS_FILTER_REDACTOR_QUARANTINE` is
  enabled

### Reporters

Reporters report leaks to some external source. The different supported types
of reporters are listed below.

Reporter settings:

- `LEAKTK_GCS_FILTER_REPORTER_KINDS` (default: `"Logger"`): is a comma
  separated list of reporter types

#### Logger

The logger reporter simply logs leaks using the function's logger.

#### Splunk

This is for posting to a Splunk HTTP Event Collector.

Required Splunk reporter settings (if the reporter is enabled):

- `LEAKTK_GCS_FILTER_SPLUNK_REPORTER_COLLECTOR`: is the URL for the Splunk HTTP
  event collector

- `LEAKTK_GCS_FILTER_SPLUNK_REPORTER_HOST`: sets the host to report in the
  events (`leaktk-gcs-filter.$bucket.$region.$project` provides a fairly
  descriptive hostname)

- `LEAKTK_GCS_FILTER_SPLUNK_REPORTER_INDEX`: sets the index the events should
  be stored under

- `LEAKTK_GCS_FILTER_SPLUNK_REPORTER_SOURCE`: sets the source you want to use
  for the events (`leaktk-gcs-filter` is a good value here)

- `LEAKTK_GCS_FILTER_SPLUNK_REPORTER_SOURCETYPE`: sets the sourcetype (`_json`
  is a good default value for this)

- `LEAKTK_GCS_FILTER_SPLUNK_REPORTER_TOKEN`: sets the token used for
  authenticating requests to the Splunk HEC

#### BigQuery

This saves results in a BigQuery database.

The project, dataset, and table are not created automatically. They must be
created using [this schema](./BigQuerySchema.json).

Required BigQuery reporter settings (if the reporter is enabled):

- `LEAKTK_GCS_FILTER_BIGQUERY_REPORTER_PROJECT_ID`: should be the project the
  BigQuery DB is in

- `LEAKTK_GCS_FILTER_BIGQUERY_REPORTER_DATASET_ID`: should be the id of the
  BigQuery dataset where the potential leaks are stored

- `LEAKTK_GCS_FILTER_BIGQUERY_REPORTER_TABLE_ID`: should be the table id in the
  dataset where the potential leaks are stored
