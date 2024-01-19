package config

// Splunk provides config options for sending info to a Splunk HTTP Event
// Collector
type Splunk struct {
	Collector  string `toml:"collector"`
	Host       string `toml:"host"`
	Index      string `toml:"index"`
	Source     string `toml:"source"`
	Sourcetype string `toml:"sourcetype"`
	Token      string `toml:"token"`
}

// BigQuery provides config options for saving results in BigQuery
type BigQuery struct {
	ProjectID string `toml:"project_id"`
	DatasetID string `toml:"dataset_id"`
	TableID   string `toml:"table_id"`
}

// Reporter contains the config for different reporter backends
type Reporter struct {
	Kind string `toml:"kind"`

	// Kinds is only used by Kind=Multi and is for combining different reporters
	Kinds []string `toml:"kinds"`

	Splunk   *Splunk   `toml:"Splunk"`
	BigQuery *BigQuery `toml:"BigQuery"`
	// Add additonal kinds of reporter backends here
}
