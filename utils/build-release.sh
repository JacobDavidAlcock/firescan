#!/bin/bash

# Build script for firescan releases
# Creates cross-platform binaries and packages them

set -e

echo "🔨 Building firescan release distributions..."

# Clean and create dist directory
rm -rf dist/
mkdir -p dist

# Define platforms and architectures
declare -A platforms=(
    ["windows/amd64"]=".exe"
    ["windows/386"]=".exe"
    ["windows/arm64"]=".exe"
    ["linux/amd64"]=""
    ["linux/386"]=""
    ["linux/arm64"]=""
    ["darwin/amd64"]=""
    ["darwin/arm64"]=""
)

# Build binaries
echo "📦 Building binaries..."
for platform in "${!platforms[@]}"; do
    IFS='/' read -r GOOS GOARCH <<< "$platform"
    EXT="${platforms[$platform]}"
    BINARY="firescan-${GOOS}-${GOARCH}${EXT}"
    
    echo "  Building ${BINARY}..."
    GOOS=$GOOS GOARCH=$GOARCH go build -ldflags="-s -w" -o "dist/${BINARY}" ./cmd/firescan
done

echo "📁 Creating archives..."
cd dist

# Create archives for each binary
for platform in "${!platforms[@]}"; do
    IFS='/' read -r GOOS GOARCH <<< "$platform"
    EXT="${platforms[$platform]}"
    BINARY="firescan-${GOOS}-${GOARCH}${EXT}"
    
    if [[ "$GOOS" == "windows" ]]; then
        ARCHIVE="${BINARY%.*}.zip"
        echo "  Creating ${ARCHIVE}..."
        zip -q "$ARCHIVE" "$BINARY"
    else
        ARCHIVE="${BINARY}.tar.gz"
        echo "  Creating ${ARCHIVE}..."
        tar -czf "$ARCHIVE" "$BINARY"
    fi
done

echo "✅ Build complete! Distribution files created in dist/:"
ls -la *.zip *.tar.gz 2>/dev/null || echo "No archives found"

echo ""
echo "📊 File sizes:"
du -h *.zip *.tar.gz 2>/dev/null || echo "No archives to show sizes for"

cd ..
echo "🎉 Release build finished!"