VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X github.com/mrgyatso/keyhole/internal/version.Version=$(VERSION)
AGENT_TARGETS := windows/amd64 windows/arm64 linux/amd64 linux/arm64 darwin/amd64 darwin/arm64
CONSENT_TARGETS := windows/amd64 windows/arm64
# The consent window is a GUI program: -H windowsgui keeps Windows from
# opening a console behind it.
CONSENT_LDFLAGS := $(LDFLAGS) -H windowsgui
WINRES_VERSION := v0.3.3
export CGO_ENABLED := 0

.PHONY: build test vet vet-cross dist winres clean

build:
	go build -ldflags "$(LDFLAGS)" -o bin/ ./cmd/...

test:
	go test ./...

vet:
	go vet ./...

# Compile-check the Windows and Linux code paths from any host.
vet-cross:
	GOOS=windows GOARCH=amd64 go vet ./...
	GOOS=linux GOARCH=amd64 go vet ./...

dist:
	@mkdir -p dist
	@for t in $(AGENT_TARGETS); do \
		os=$${t%/*}; arch=$${t#*/}; ext=; [ $$os = windows ] && ext=.exe; \
		echo "keyhole-agent $$os/$$arch"; \
		GOOS=$$os GOARCH=$$arch go build -ldflags "$(LDFLAGS)" -o dist/keyhole-agent-$$os-$$arch$$ext ./cmd/keyhole-agent || exit 1; \
	done
	@for t in $(CONSENT_TARGETS); do \
		os=$${t%/*}; arch=$${t#*/}; \
		echo "keyhole-consent $$os/$$arch"; \
		GOOS=$$os GOARCH=$$arch go build -ldflags "$(CONSENT_LDFLAGS)" -o dist/keyhole-consent-$$os-$$arch.exe ./cmd/keyhole-consent || exit 1; \
	done
	GOOS=linux GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o dist/keyhole-relay-linux-amd64 ./cmd/keyhole-relay
	cd dist && shasum -a 256 keyhole-* > SHA256SUMS

# Regenerate the consent window's embedded Windows resources (side-by-side
# manifest: common controls v6, per-monitor v2 DPI, asInvoker). The .syso
# files are checked in so a plain `go build` produces a correct binary; run
# this only after editing cmd/keyhole-consent/winres/winres.json.
winres:
	cd cmd/keyhole-consent && go run github.com/tc-hib/go-winres@$(WINRES_VERSION) make --arch amd64,arm64

clean:
	rm -rf bin dist
