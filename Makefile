GO ?= go

.PHONY: all fmt vet test race bench yaegi-test clean

all: fmt vet test

fmt:
	gofmt -l -w .

vet:
	$(GO) vet ./...

test:
	$(GO) test ./...

race:
	$(GO) test -race ./...

bench:
	$(GO) test -run '^$$' -bench . -benchmem ./...

# Run the unit tests through Yaegi, the Go interpreter used by Traefik.
yaegi-test:
	$(GO) run github.com/traefik/yaegi/cmd/yaegi@latest test -v .

clean:
	$(GO) clean
