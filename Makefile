BINARY := anansi
GOFLAGS := -ldflags="-s -w"

.PHONY: all build test lint vet clean

all: lint vet test build

build:
	go build $(GOFLAGS) -o $(BINARY) .

test:
	go test ./... -count=1 -timeout 60s

vet:
	go vet ./...

lint:
	golangci-lint run ./...

clean:
	rm -f $(BINARY)
	rm -rf releases/
