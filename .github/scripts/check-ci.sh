#!/bin/bash
# CI/CD Health Check Script

set -e

echo "🔍 FireScan CI/CD Health Check"
echo "================================"
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Track failures
FAILURES=0

# Function to run check
run_check() {
    local name=$1
    local command=$2
    
    echo -n "Checking $name... "
    
    if eval "$command" > /tmp/ci-check.log 2>&1; then
        echo -e "${GREEN}✓ PASS${NC}"
        return 0
    else
        echo -e "${RED}✗ FAIL${NC}"
        echo "  Error details:"
        cat /tmp/ci-check.log | head -20
        FAILURES=$((FAILURES + 1))
        return 1
    fi
}

# Check Go installation
echo "📋 Prerequisites"
echo "----------------"
run_check "Go installation" "go version"
echo ""

# Check dependencies
echo "📦 Dependencies"
echo "---------------"
run_check "Go modules" "go mod verify"
run_check "Download dependencies" "go mod download"
echo ""

# Run tests
echo "🧪 Tests"
echo "--------"
run_check "Unit tests" "go test ./..."
run_check "Race detection" "go test -race ./..."
echo ""

# Run go vet
echo "🔧 Go Vet"
echo "---------"
run_check "Go vet" "go vet ./..."
echo ""

# Check if golangci-lint is installed
if command -v golangci-lint &> /dev/null; then
    echo "🎨 Linting"
    echo "----------"
    run_check "golangci-lint" "golangci-lint run --timeout=5m"
    echo ""
else
    echo -e "${YELLOW}⚠ golangci-lint not installed (skipping)${NC}"
    echo "  Install: go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest"
    echo ""
fi

# Check if gosec is installed
if command -v gosec &> /dev/null; then
    echo "🔒 Security Scan"
    echo "----------------"
    run_check "gosec" "gosec -quiet ./..."
    echo ""
else
    echo -e "${YELLOW}⚠ gosec not installed (skipping)${NC}"
    echo "  Install: go install github.com/securego/gosec/v2/cmd/gosec@latest"
    echo ""
fi

# Check builds
echo "🏗️  Build Check"
echo "---------------"
run_check "Build (current platform)" "go build -o /tmp/firescan-test ./cmd/firescan"
run_check "Build (Linux AMD64)" "GOOS=linux GOARCH=amd64 go build -o /tmp/firescan-linux ./cmd/firescan"
run_check "Build (Windows AMD64)" "GOOS=windows GOARCH=amd64 go build -o /tmp/firescan.exe ./cmd/firescan"
run_check "Build (macOS ARM64)" "GOOS=darwin GOARCH=arm64 go build -o /tmp/firescan-mac ./cmd/firescan"
echo ""

# Cleanup
rm -f /tmp/firescan-test /tmp/firescan-linux /tmp/firescan.exe /tmp/firescan-mac /tmp/ci-check.log

# Summary
echo "================================"
if [ $FAILURES -eq 0 ]; then
    echo -e "${GREEN}✅ All checks passed!${NC}"
    echo ""
    echo "Your code is ready to push. CI/CD will likely succeed."
    exit 0
else
    echo -e "${RED}❌ $FAILURES check(s) failed${NC}"
    echo ""
    echo "Please fix the issues above before pushing."
    echo "CI/CD will fail with these errors."
    exit 1
fi
