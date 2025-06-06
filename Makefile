# Default Settings
LEAKTK_GCS_FILTER_CONCURRENCY ?= 10
LEAKTK_GCS_FILTER_CPU ?= 2
LEAKTK_GCS_FILTER_MEMORY ?= 256Mi
LEAKTK_GCS_FILTER_TIMEOUT ?= 5s
LEAKTK_PATTERN_SERVER_URL ?= https://raw.githubusercontent.com/leaktk/patterns/main/target

# Build the deploy flags
DEPLOY_FLAGS := --gen2 --runtime=go123 --region=$(LEAKTK_GCS_FILTER_REGION)
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
		'$(LEAKTK_PATTERN_SERVER_URL)/patterns/gitleaks/7.6.1' \
		| grep -vE '^\s*(#|$$)' > 'dist/config/gitleaks.toml'

.PHONY: format
format:
	cd src && go fmt ./...

.PHONY: lint
lint:
	cd src && golint ./...

.PHONY: deploy
deploy: .env.yaml dist
	cd dist
	gcloud functions deploy leaktk-gcs-filter $(DEPLOY_FLAGS)

.PHONY: unittest
unittest: clean dist
	cd dist && go test

.PHONY: test
test: lint unittest

.PHONY: security-report
security-report:
	trivy fs --scanners vuln .

.PHONY: update
update:
	cd src && go get -u ./... && go mod tidy
