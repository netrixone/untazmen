# untazmen — strip TZSP encapsulation from pcap/pcapng
# Modern Go Makefile: make help (default), make build, make test, make install

BINARY    := untazmen
GO       := go
GOFLAGS  :=
VERSION  := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS  := -X main.version=$(VERSION)

.PHONY: all build test clean install run help vet fmt

all: build

help:
	@echo "Targets:"
	@echo "  make          same as make build"
	@echo "  make build    build $(BINARY)"
	@echo "  make test     run tests"
	@echo "  make vet      run go vet"
	@echo "  make fmt      run gofmt -s -w"
	@echo "  make run      run binary (e.g. make run ARGS='-i file.pcapng -o -')"
	@echo "  make install  install to $$GOBIN or $$GOPATH/bin"
	@echo "  make clean    remove binary and coverage artifacts"

build:
	$(GO) build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o $(BINARY) .

test:
	$(GO) test $(GOFLAGS) ./...

vet:
	$(GO) vet ./...

fmt:
	$(GO) fmt ./...
	gofmt -s -w .

run: build
	./$(BINARY) $(ARGS)

install:
	$(GO) install $(GOFLAGS) -ldflags '$(LDFLAGS)' .

clean:
	rm -f $(BINARY)
	rm -f coverage.out coverage.html
