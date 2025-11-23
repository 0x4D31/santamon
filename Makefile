.PHONY: build build-arm64 build-amd64 build-all test test-race test-coverage lint clean install uninstall start stop logs validate stats run deps help

# Default target
.DEFAULT_GOAL := help

# Binary name
BINARY=santamon

# Build directory
BUILD_DIR=.

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOTEST=$(GOCMD) test
GOMOD=$(GOCMD) mod
GOGET=$(GOCMD) get

# Build the binary
build:
	@echo "Building $(BINARY)..."
	$(GOBUILD) -o $(BUILD_DIR)/$(BINARY) ./cmd/santamon

# Build for macOS ARM64
build-arm64:
	@echo "Building $(BINARY) for darwin/arm64..."
	GOOS=darwin GOARCH=arm64 $(GOBUILD) -o $(BUILD_DIR)/$(BINARY)-arm64 ./cmd/santamon

# Build for macOS AMD64
build-amd64:
	@echo "Building $(BINARY) for darwin/amd64..."
	GOOS=darwin GOARCH=amd64 $(GOBUILD) -o $(BUILD_DIR)/$(BINARY)-amd64 ./cmd/santamon

# Build all architectures
build-all: build-arm64 build-amd64
	@echo "Built binaries for all architectures"

# Run tests
test:
	@echo "Running tests..."
	$(GOTEST) -v ./...

# Run tests with race detector
test-race:
	@echo "Running tests with race detector..."
	$(GOTEST) -race ./...

# Run tests with coverage
test-coverage:
	@echo "Running tests with coverage..."
	$(GOTEST) -coverprofile=coverage.out -covermode=atomic ./...

# Run golangci-lint
lint:
	@echo "Running golangci-lint..."
	golangci-lint run

# Clean build artifacts
clean:
	@echo "Cleaning..."
	rm -f $(BUILD_DIR)/$(BINARY)
	rm -f $(BUILD_DIR)/$(BINARY)-arm64
	rm -f $(BUILD_DIR)/$(BINARY)-amd64
	rm -f *.db
	rm -f *.db-shm
	rm -f *.db-wal
	rm -f coverage.out

# Download dependencies
deps:
	@echo "Downloading dependencies..."
	$(GOMOD) download
	$(GOMOD) tidy

# Install (requires root)
install: build
	@echo "Installing $(BINARY)..."
	sudo ./scripts/install.sh

# Uninstall (requires root)
uninstall:
	@echo "Uninstalling $(BINARY)..."
	sudo launchctl bootout system /Library/LaunchDaemons/com.santamon.plist 2>/dev/null || true
	sudo rm -f /Library/LaunchDaemons/com.santamon.plist
	sudo rm -f /usr/local/bin/santamon
	@echo "Note: Config files in /etc/santamon and data in /var/lib/santamon were preserved"

# Start the service
start:
	@echo "Starting santamon service..."
	sudo launchctl bootstrap system /Library/LaunchDaemons/com.santamon.plist

# Stop the service
stop:
	@echo "Stopping santamon service..."
	sudo launchctl bootout system /Library/LaunchDaemons/com.santamon.plist

# Show logs
logs:
	@tail -f /var/log/santamon.log

# Validate rules (dev config)
validate:
	@SANTAMON_API_KEY=test-key-1234567890 ./$(BINARY) rules validate --config configs/santamon.yaml

# Show database stats
stats:
	@./$(BINARY) db stats

# Quick dev run (with sudo and env var)
run: build
	@sudo SANTAMON_API_KEY=test-key-1234567890 ./$(BINARY) run --config configs/santamon.yaml

# Help
help:
	@echo "Santamon Makefile"
	@echo ""
	@echo "Build targets:"
	@echo "  make build        - Build the binary for current arch"
	@echo "  make build-arm64  - Build for macOS ARM64"
	@echo "  make build-amd64  - Build for macOS AMD64"
	@echo "  make build-all    - Build for all architectures"
	@echo ""
	@echo "Test targets:"
	@echo "  make test         - Run tests"
	@echo "  make test-race    - Run tests with race detector"
	@echo "  make test-coverage- Run tests with coverage"
	@echo "  make lint         - Run golangci-lint"
	@echo ""
	@echo "Development:"
	@echo "  make clean        - Clean build artifacts"
	@echo "  make deps         - Download dependencies"
	@echo "  make validate     - Validate rules"
	@echo "  make run          - Quick dev run"
	@echo ""
	@echo "Service management:"
	@echo "  make install      - Install (requires sudo)"
	@echo "  make uninstall    - Uninstall (requires sudo)"
	@echo "  make start        - Start the service"
	@echo "  make stop         - Stop the service"
	@echo ""
	@echo "Monitoring:"
	@echo "  make logs         - Tail log file"
	@echo "  make stats        - Show DB statistics"
