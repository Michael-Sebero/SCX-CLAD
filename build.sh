#!/bin/bash
# Build script for scx_imperator

set -e

echo "=== Building scx_imperator ==="

# Build release version with native CPU optimizations
# This enables all CPU-specific features (AVX-512, etc.) for maximum performance
RUSTFLAGS="-C target-cpu=native" cargo build --release

echo ""
echo "=== Build complete ==="
echo "Binary: ./target/release/scx_imperator"
echo ""
echo "Run with: sudo ./start.sh"
