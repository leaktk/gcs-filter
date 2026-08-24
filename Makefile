# Default Settings
LEAKTK_GCS_FILTER_CONCURRENCY ?= 10
LEAKTK_GCS_FILTER_CPU ?= 2
LEAKTK_GCS_FILTER_MEMORY ?= 256Mi
LEAKTK_GCS_FILTER_TIMEOUT ?= 5s
LEAKTK_PATTERN_SERVER_URL ?= https://raw.githubusercontent.com/leaktk/patterns/main/target
LEAKTK_PATTERNS_GITLEAKS_VERSION ?= 8.27.0

# Build the deploy flags
DEPLOY_FLAGS := --gen2 --runtime=go125 --region=$(LEAKTK_GCS_FILTER_REGION)
DEPLOY_FLAGS += --source=dist --entry-point=AnalyzeObject
DEPLOY_FLAGS += --trigger-bucket=$(LEAKTK_GCS_FILTER_TRIGGER_BUCKET) --project=$(LEAKTK_GCS_FILTER_PROJECT)
DEPLOY_FLAGS += --cpu=$(LEAKTK_GCS_FILTER_CPU) --memory=$(LEAKTK_GCS_FILTER_MEMORY)
DEPLOY_FLAGS += --concurrency=$(LEAKTK_GCS_FILTER_CONCURRENCY) --timeout=$(LEAKTK_GCS_FILTER_TIMEOUT)
DEPLOY_FLAGS += --env-vars-file=.env.yaml

.PHONY: clean
clean:
	git clean -dfX

.env.yaml:
	./scripts/gen-env-vars-file > .env.yaml

dist:
	rm -rf dist
	cp -r src dist
	curl --fail $(LEAKTK_PATTERN_SERVER_CURL_FLAGS) \
		'$(LEAKTK_PATTERN_SERVER_URL)/patterns/gitleaks/$(LEAKTK_PATTERNS_GITLEAKS_VERSION)' \
		| grep -vE '^\s*(#|$$)' > 'dist/config/gitleaks.toml'

.PHONY: import
import:
	env -C src goimports -local github.com/leaktk/gcs-filter -l -w . && go mod tidy

.PHONY: format
format:
	env -C src go fmt ./...

.PHONY: vet
vet: dist
	env -C dist go vet ./...

.PHONY: lint
lint: dist vet
	env -C dist golangci-lint run

.PHONY: deploy
deploy: .env.yaml dist
	env -C dist gcloud functions deploy leaktk-gcs-filter $(DEPLOY_FLAGS)

.PHONY: unittest
unittest: dist
	env -C dist go test

.PHONY: test
# Force the pattern server URL for the tests
test: LEAKTK_PATTERN_SERVER_URL = https://raw.githubusercontent.com/leaktk/patterns/main/target
test: clean format vet lint unittest

.PHONY: security-report
security-report:
	trivy fs --scanners vuln ./src/

.PHONY: update
update:
	env -C src go get -u ./... && go mod tidy
