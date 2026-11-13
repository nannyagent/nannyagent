.PHONY: build run clean test install snapshot release help

VERSION := $(shell cat VERSION)
BINARY_NAME := nannyagent

build:
	go build -ldflags "-X main.Version=$(VERSION)" -o $(BINARY_NAME) .

run: build
	./$(BINARY_NAME)

clean:
	rm -f $(BINARY_NAME)
	rm -rf dist/

test:
	go test -v ./...

install:
	go mod tidy
	go mod download

snapshot:
	goreleaser build --snapshot --clean

snapshot-single:
	goreleaser build --snapshot --clean --single-target

release:
	goreleaser release --clean

check:
	goreleaser check

install-system: build
	sudo cp $(BINARY_NAME) /usr/sbin/
	sudo chmod +x /usr/sbin/$(BINARY_NAME)
	sudo mkdir -p /etc/nannyagent
	sudo bash -c 'cat > /etc/nannyagent/config.yaml <<EOF\nnannyapi_url: https://api.nannyai.dev\nportal_url: https://nannyai.dev\ntoken_path: /var/lib/nannyagent/token.json\nmetrics_interval: 30\ndebug: false\nEOF'
	sudo chmod 600 /etc/nannyagent/config.yaml
	sudo cp nannyagent.service /etc/systemd/system/
	sudo systemctl daemon-reload
	@echo "Service installed. Configure /etc/nannyagent/config.yaml then run: sudo systemctl start nannyagent"

fmt:
	go fmt ./...

lint:
	golangci-lint run

help:
	@echo "NannyAgent Build System (GoReleaser)"
	@echo ""
	@echo "Development:"
	@echo "  make build              - Build for current platform"
	@echo "  make run                - Build and run"
	@echo "  make test               - Run tests"
	@echo "  make clean              - Clean artifacts"
	@echo ""
	@echo "GoReleaser:"
	@echo "  make snapshot           - Build all platforms (snapshot)"
	@echo "  make snapshot-single    - Build current platform only"
	@echo "  make release            - Create GitHub release"
	@echo "  make check              - Validate goreleaser config"
	@echo ""
	@echo "Deployment:"
	@echo "  make install-system     - Install as systemd service"
	@echo ""
	@echo "Version: $(VERSION)"
