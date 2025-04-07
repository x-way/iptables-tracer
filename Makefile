.PHONY: build test lint format coverage clean all

SRCDIR=.
BINNAME=iptables-tracer

all: format lint test build

build:
	go build -o $(BINNAME) $(SRCDIR)
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o $(BINNAME).aarch64 $(SRCDIR)
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o $(BINNAME).amd64 $(SRCDIR)

test:
	go test -v ./...

lint:
	go vet -v ./...
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	golangci-lint run
	go install honnef.co/go/tools/cmd/staticcheck@latest
	staticcheck -checks all ./...
	go install golang.org/x/vuln/cmd/govulncheck@latest
	govulncheck ./...

format:
	go fmt ./...
	go install mvdan.cc/gofumpt@latest
	gofumpt -w .

coverage:
	go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

clean:
	rm -f $(BINNAME) $(BINNAME).aarch64 $(BINNAME).amd64 coverage.out coverage.html
