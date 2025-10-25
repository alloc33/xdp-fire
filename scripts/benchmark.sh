#!/bin/bash
# Benchmark script for xdp-fire XDP filter
# Tests packet filtering performance on loopback interface

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}=== xdp-fire Benchmark ===${NC}"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Error: This script must be run as root${NC}"
    exit 1
fi

# Check if iperf3 is installed
if ! command -v iperf3 &> /dev/null; then
    echo -e "${YELLOW}Installing iperf3...${NC}"
    apt-get update && apt-get install -y iperf3
fi

DURATION=10
IFACE="lo"
PROJECT_DIR="/root/xdp-fire"
BINARY="$PROJECT_DIR/target/release/xdp-fire"

# Build if needed
if [ ! -f "$BINARY" ]; then
    echo -e "${YELLOW}Building xdp-fire...${NC}"
    cd "$PROJECT_DIR" && cargo build --release
fi

# Cleanup function
cleanup() {
    echo -e "\n${YELLOW}Cleaning up...${NC}"
    pkill -f iperf3 || true
    pkill -f xdp-fire || true
    sleep 1
}

trap cleanup EXIT

# Function to run iperf3 and measure
run_benchmark() {
    local test_name=$1
    local filter_enabled=$2

    echo -e "\n${GREEN}--- Test: $test_name ---${NC}"

    # Start iperf3 server in background
    iperf3 -s -p 5201 > /dev/null 2>&1 &
    IPERF_PID=$!
    sleep 2

    # Start XDP program if needed
    if [ "$filter_enabled" = "true" ]; then
        echo -e "${YELLOW}Starting XDP filter on $IFACE...${NC}"
        "$BINARY" --iface "$IFACE" > /dev/null 2>&1 &
        XDP_PID=$!
        sleep 2

        # Configure to log only (don't drop packets)
        "$BINARY" set-log-level -l 0  # None - no logging overhead
        "$BINARY" add-rule -p 5201 -a 2  # LogOnly for port 5201
    fi

    # Run iperf3 client
    echo -e "${YELLOW}Running iperf3 for ${DURATION}s...${NC}"
    RESULT=$(iperf3 -c 127.0.0.1 -p 5201 -t $DURATION -P 4 2>&1)

    # Extract throughput
    THROUGHPUT=$(echo "$RESULT" | grep "sender" | tail -1 | awk '{print $(NF-2), $(NF-1)}')

    echo -e "${GREEN}Throughput: $THROUGHPUT${NC}"

    # Show XDP stats if enabled
    if [ "$filter_enabled" = "true" ]; then
        echo -e "${YELLOW}XDP Statistics:${NC}"
        "$BINARY" show-stats 2>/dev/null || echo "Stats not available"
    fi

    # Cleanup this test
    kill $IPERF_PID 2>/dev/null || true
    if [ "$filter_enabled" = "true" ]; then
        kill $XDP_PID 2>/dev/null || true
        sleep 1
    fi

    echo "$THROUGHPUT"
}

# Run benchmarks
echo -e "\n${GREEN}Starting benchmarks (each test runs for ${DURATION}s)...${NC}"

# Baseline without XDP
BASELINE=$(run_benchmark "Baseline (No XDP)" "false")

# With XDP filter (pass-through mode)
XDP_RESULT=$(run_benchmark "With XDP Filter (LogOnly)" "true")

# Summary
echo -e "\n${GREEN}=== Benchmark Results ===${NC}"
echo -e "Baseline (No XDP):        $BASELINE"
echo -e "With XDP (LogOnly):       $XDP_RESULT"
echo ""
echo -e "${GREEN}✓ Benchmark complete!${NC}"
