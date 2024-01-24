# The following make vars must be provided to do a deploy:
#
# GCF_PROJECT - The project to deploy to
# GCF_REGION - The region to deploy the function to
# GCS_BUCKET - The bucket that should trigger the function
# LEAKTK_PATTERN_SERVER_CURL_FLAGS - Flags for providing auth to a pattern server
#
# The following flags can be provided if needed
#
# GCF_CONCURRENCY  - How many connections a single function can take at once (default: 10)
# GCF_CPU - How many CPUs the function should be given (default: 2)
# GCF_MEMORY - much the function should be given (default: 256Mi)
# GCF_TIMEOUT - The timeout in seconds for the function (default: 5s)
# EXCLUDE_LIST_URL - A list regexes to ignore in file paths
# EXCLUDE_LIST_CURL_FLAGS - Flags for providing auth to the exclude list server
# LEAKTK_PATTERN_SERVER_URL - The URL for the pattern server
# LEAKTK_GCS_FILTER_ALLOW_REMOVE - allow the function to remove files with leaks
#                                  (default: true)
# LEAK_REPORTER_CONFIG - The config for where reports of leaks should go.
#                        The supported values are currently Splunk, BigQuery
#                        and Logger. Some take extra config that can be seen
#                        from the src/config/config.go structs.

define DEFAULT_LEAK_REPORTER_CONFIG
kind="Logger"
endef

# Set env vars for the deploy
LEAKTK_GCS_FILTER_ALLOW_REMOVE ?= true

# Collect the env vars to pass to the gcloud command
ENV_VARS := LEAKTK_GCS_FILTER_ALLOW_REMOVE=$(LEAKTK_GCS_FILTER_ALLOW_REMOVE)

# Settings
GCF_CONCURRENCY ?= 10
GCF_CPU ?= 2
GCF_MEMORY ?= 256Mi
GCF_TIMEOUT ?= 5s
GCF_DEPLOY_FLAGS := --gen2 --runtime=go121 --region=$(GCF_REGION)
GCF_DEPLOY_FLAGS += --source=dist --entry-point=AnalyzeObject
GCF_DEPLOY_FLAGS += --trigger-bucket=$(GCS_BUCKET) --project=$(GCF_PROJECT)
GCF_DEPLOY_FLAGS += --cpu=$(GCF_CPU) --memory=$(GCF_MEMORY)
GCF_DEPLOY_FLAGS += --concurrency=$(GCF_CONCURRENCY) --timeout=$(GCF_TIMEOUT)
GCF_DEPLOY_FLAGS += --set-env-vars=$(ENV_VARS)
LEAKTK_PATTERN_SERVER_URL ?= https://raw.githubusercontent.com/leaktk/patterns/main/target
LEAK_REPORTER_CONFIG ?= $(DEFAULT_LEAK_REPORTER_CONFIG)

export LEAK_REPORTER_CONFIG

.PHONY: clean
clean:
	git clean -dfX

dist/config/gitleaks.toml:
	curl --fail $(LEAKTK_PATTERN_SERVER_CURL_FLAGS) \
		'$(LEAKTK_PATTERN_SERVER_URL)/patterns/gitleaks/7.6.1' \
		| grep -vE '^\s*(#|$$)' > '$@'

dist/config/reporter.toml:
	echo "$$LEAK_REPORTER_CONFIG" > '$@'

dist/config/exclude-list.txt:
	if [[ -n '$(EXCLUDE_LIST_URL)' ]]; \
		then curl --fail $(EXCLUDE_LIST_CURL_FLAGS) -o '$@' '$(EXCLUDE_LIST_URL)'; \
		else touch '$@'; \
	fi

dist:
	rm -rf dist
	cp -r src dist
	make \
		dist/config/exclude-list.txt \
		dist/config/reporter.toml \
		dist/config/gitleaks.toml

.PHONY: format
format:
	cd src && go fmt ./...

.PHONY: lint
lint:
	cd src && golint ./...

.PHONY: deploy
deploy: dist
	cd dist
	gcloud functions deploy leaktk-gcs-filter $(GCF_DEPLOY_FLAGS)

unittest: clean dist
	cd dist && go test

test: lint unittest
