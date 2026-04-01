NAME := wafsrv
GOFLAGS := -mod=vendor

PKG := `go list ${GOFLAGS} -f {{.Dir}} ./...`

ifeq ($(RACE),1)
	GOFLAGS+=-race
endif

LINT_VERSION := v2.11.0

MAIN := ${NAME}/cmd/${NAME}

.PHONY: *

init:
	@cp -n cfg/local.toml.dist cfg/local.toml

show-env:
	@echo "NAME=$(NAME)"
	@echo "GOFLAGS=$(GOFLAGS)"

tools:
	@curl -sfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(go env GOPATH)/bin ${LINT_VERSION}

fmt:
	@golangci-lint fmt

lint:
	@golangci-lint version
	@golangci-lint config verify
	@golangci-lint run

build:
	@CGO_ENABLED=0 go build $(GOFLAGS) -o ${NAME} $(MAIN)

run:
	@go run $(GOFLAGS) $(MAIN) -config=cfg/local.toml -verbose

test:
	@echo "Running tests"
	@go test -count=1 $(GOFLAGS) -coverprofile=coverage.txt -covermode count $(PKG)

test-short:
	@go test $(GOFLAGS) -short ./...

mod:
	@go mod tidy
	@go mod vendor

bench:
	@go test -bench=. -benchmem ./internal/...

e2e:
	@go test -v -count=1 -timeout 60s -race ./e2e/

# Aerospike integration tests
AEROSPIKE_COMPOSE := deployments/docker-compose.aerospike.yml

aerospike:
	@echo "Starting Aerospike..."
	@docker compose -f $(AEROSPIKE_COMPOSE) up -d --wait
	@echo "Running Aerospike integration tests..."
	@AEROSPIKE_HOST=127.0.0.1:3000 go test -v -count=1 -timeout 120s ./internal/waf/storage/ -run Aerospike; \
		EXIT=$$?; \
		docker compose -f $(AEROSPIKE_COMPOSE) down; \
		exit $$EXIT

e2e-aerospike:
	@echo "Starting Aerospike..."
	@docker compose -f $(AEROSPIKE_COMPOSE) up -d --wait
	@echo "Running e2e tests with Aerospike storage..."
	@E2E_CONFIG=cfg/e2e-aerospike.toml go test -v -count=1 -timeout 120s -race ./e2e/; \
		EXIT=$$?; \
		docker compose -f $(AEROSPIKE_COMPOSE) down; \
		exit $$EXIT

aerospike-up:
	@docker compose -f $(AEROSPIKE_COMPOSE) up -d --wait

aerospike-down:
	@docker compose -f $(AEROSPIKE_COMPOSE) down

# GeoIP databases (db-ip.com — free, no registration)
GEODATA_DIR := internal/waf/ip/data
DBIP_MONTH := $(shell date +%Y-%m)

geo-download: $(GEODATA_DIR)/dbip-country-lite.mmdb $(GEODATA_DIR)/dbip-asn-lite.mmdb

$(GEODATA_DIR)/dbip-country-lite.mmdb:
	@mkdir -p $(GEODATA_DIR)
	@echo "Downloading dbip-country-lite..."
	@curl -sSfL "https://download.db-ip.com/free/dbip-country-lite-$(DBIP_MONTH).mmdb.gz" | gunzip > $@

$(GEODATA_DIR)/dbip-asn-lite.mmdb:
	@mkdir -p $(GEODATA_DIR)
	@echo "Downloading dbip-asn-lite..."
	@curl -sSfL "https://download.db-ip.com/free/dbip-asn-lite-$(DBIP_MONTH).mmdb.gz" | gunzip > $@

geo-clean:
	@rm -rf $(GEODATA_DIR)/*.mmdb
