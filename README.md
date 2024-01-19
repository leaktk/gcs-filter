# leaktk-gcs-filter

Filter objects containing leaks from Google Cloud Storage

## Redaction

Only rules tagged `type:secret` and not `group:leaktk-testing` will result
in objects being redacted.

To put the function in "testing mode", make sure all of the rules provided
are tagged with `group:leaktk-testing`.

If a rule does trigger a redaction, the whole object will be replaced
with a message containing a notice that the object was removed and why.

## Settings

The settings for this project are passed in via env vars during `make deploy`.
See top of the the [Makefile](./Makefile) for a description of those env vars.

## Reporters

Reporters report links to some external source. The different supported types
of reporters are listed below.

The `LEAK_REPORTER_CONFIG` env variable can be set during `make deploy` to
write the reporter.toml to the right location during the deploy process.

### Multi

This is for combining any of the other log types below.

When creating the reporting.toml through the `LEAK_REPORTER_CONFIG` variable,
it should look something like this:

```toml
# Note you set kinds (plural) instead of kind to get a multi reporter
kinds=["Logger", "Splunk", "BigQuery"]

[Splunk]
...

[BigQuery]
...
```

You can swap the order or leave any kind out you want.

### Logger

The logger reporter simply logs leaks using the function's logger.

When creating the reporting.toml through the `LEAK_REPORTER_CONFIG` variable,
it should look something like this:

```toml
kind="Logger"
```

This is also the default if `LEAK_REPORTER_CONFIG` isn't set.

### Splunk

This is for posting to a Splunk HTTP Event Collector.

When creating the reporting.toml through the `LEAK_REPORTER_CONFIG` variable,
it should look something like this:

```toml
kind="Splunk"

[Splunk]
collector="https://replace_me_with_the_correct_collector_url"
host="replace_me_with_the_host_name_to_report"
index="replace_me_with_the_index_you_want_to_use"
source="leaktk-gcs-filter"
sourcetype="_json"
token="replace_me_the_splunk_hec_token"
```

### BigQuery

The project, dataset, and table are not created automatically. They must be
created using [this schema](./BigQuerySchema.json).

When creating the reporting.toml through the `LEAK_REPORTER_CONFIG` variable,
it should look something like this:

```toml
kind="BigQuery"

[BigQuery]
project_id="replace-with-project-id"
dataset_id="replace_with_dataset_id"
table_id="replace_with_table_id"
```
