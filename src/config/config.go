package config

import (
	// Used to pull in embeded files when dist is built
	_ "embed"
	"regexp"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/leaktk/gcs-filter/logging"
	"github.com/leaktk/gitleaks7/v2/config"
)

//go:embed gitleaks.toml
var gitleaksConfig string

//go:embed reporter.toml
var reporterConfig string

//go:embed exclude-list.txt
var rawExcludeList string

var excludeList []*regexp.Regexp

func init() {
	for i, item := range strings.Split(strings.ReplaceAll(rawExcludeList, "\r\n", "\n"), "\n") {
		item = strings.TrimSpace(item)

		if len(item) == 0 || strings.HasPrefix(item, "#") {
			continue
		}

		regex, err := regexp.Compile(item)

		if err != nil {
			logging.Fatal("regex.Compile[%d]: error=\"%w\"", i, err.Error())
		}

		excludeList = append(excludeList, regex)
	}
}

// NewConfig creates a gitleaks compatible config for this scanner from the
// embeded config added during the compile
func NewConfig() (config.Config, error) {
	var cfg config.Config
	tomlLoader := config.TomlLoader{}

	_, err := toml.Decode(gitleaksConfig, &tomlLoader)

	if err != nil {
		return cfg, err
	}

	return tomlLoader.Parse()
}

// PathExcluded checks to see if a specific path should be excluded from
// copying before pulling the object's resources
func PathExcluded(filePath string) bool {
	for _, re := range excludeList {
		if re.MatchString(filePath) {
			return true
		}
	}

	return false
}

// NewReporterConfig loads the report config from ./report.toml
func NewReporterConfig() (Reporter, error) {
	reporter := Reporter{}
	_, err := toml.Decode(reporterConfig, &reporter)
	return reporter, err
}
