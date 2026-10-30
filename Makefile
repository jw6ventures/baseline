VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.Version=$(VERSION)
TEST_DB ?= postgres://baseline:test@127.0.0.1:55433/baseline?sslmode=disable

.PHONY: build build-agent test test-db test-db-stop vendor proto image image-agent

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/baseline-server ./cmd/baseline-server

build-agent:
	for arch in amd64 arm64; do \
		CGO_ENABLED=0 GOOS=linux GOARCH=$$arch go build -trimpath -ldflags "$(LDFLAGS)" \
			-o bin/agent/baseline-agent-linux-$$arch ./cmd/baseline-agent; \
	done

test:
	go vet ./...
	go test -race ./...

# Unit tests plus database tests against a throwaway Postgres container,
# bound to loopback only. Its data lives in RAM: every test creates a
# database.
test-db:
	@docker inspect baseline-testdb >/dev/null 2>&1 || \
		docker run -d --rm --name baseline-testdb -e POSTGRES_USER=baseline -e POSTGRES_PASSWORD=test \
			-e POSTGRES_DB=baseline -p 127.0.0.1:55433:5432 \
			--tmpfs /var/lib/postgresql:rw,size=1g postgres:18 \
			-c fsync=off -c full_page_writes=off -c max_wal_size=64MB >/dev/null
	@until docker exec baseline-testdb pg_isready -U baseline -d baseline >/dev/null 2>&1; do sleep 0.5; done
	go vet ./...
	BASELINE_TEST_DB_URL='$(TEST_DB)' go test -race ./...

test-db-stop:
	docker rm -f baseline-testdb

# Dependencies are committed (docs/architecture.md §9).
vendor:
	go mod tidy
	go mod vendor

# Regenerates api/agent/v1 from agent.proto. The output is committed, so
# this only runs when the protocol changes. Needs protoc on PATH.
PROTOC_GEN_GO := google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.12
PROTOC_GEN_GO_GRPC := google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.6.2
proto:
	GOBIN=$(CURDIR)/bin go install $(PROTOC_GEN_GO)
	GOBIN=$(CURDIR)/bin go install $(PROTOC_GEN_GO_GRPC)
	PATH=$(CURDIR)/bin:$$PATH protoc -I api --go_out=. --go_opt=module=github.com/jw6ventures/baseline \
		--go-grpc_out=. --go-grpc_opt=module=github.com/jw6ventures/baseline api/agent/v1/agent.proto

image:
	docker build --build-arg VERSION=$(VERSION) -t baseline-server:$(VERSION) .

# The cluster agent's image (deploy/k8s/baseline-agent.yaml).
image-agent:
	docker build --target agent --build-arg VERSION=$(VERSION) -t baseline-agent:$(VERSION) .
