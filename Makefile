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
# Pin the interpreter version so CI and local runs agree.
YAEGI_VERSION ?= v0.16.3

yaegi-test:
	$(GO) run github.com/traefik/yaegi/cmd/yaegi@$(YAEGI_VERSION) test -v .

clean:
	$(GO) clean
