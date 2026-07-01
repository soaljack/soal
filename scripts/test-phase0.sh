#!/usr/bin/env bash
#
# Phase 0 End-to-End Test Script for Soal
#
# Usage:
#   ./scripts/test-phase0.sh
#
# This performs realistic testing of the Phase 0 implementation:
# - Vaults with encryption on/off
# - Adding directories and files
# - Chunk deduplication
# - Snapshot history
# - Full restore fidelity check
# - Encryption at rest verification
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
SOAL_BIN="${PROJECT_ROOT}/target/debug/soal"

if [[ ! -x "$SOAL_BIN" ]]; then
    echo "Building debug for testing..."
    (cd "$PROJECT_ROOT" && cargo build) || (cd "$PROJECT_ROOT" && source "$HOME/.cargo/env" 2>/dev/null || true && cargo build)
fi

echo "=== Soal Phase 0 End-to-End Tests ==="
echo

# Isolated environment
TEST_ROOT=$(mktemp -d)
export HOME="$TEST_ROOT"

cleanup() { rm -rf "$TEST_ROOT"; }
trap cleanup EXIT

TESTDATA="$TEST_ROOT/original"
PRISTINE="$TEST_ROOT/pristine"
mkdir -p "$TESTDATA/subdir" "$PRISTINE"

echo "File A content for deduplication test" > "$TESTDATA/file-a.txt"
echo "File B different content here" > "$TESTDATA/file-b.txt"
echo "Deeply nested content" > "$TESTDATA/subdir/nested.txt"
cp "$TESTDATA/file-a.txt" "$TESTDATA/file-a-dup.txt"

# Keep a pristine copy before any modifications for fidelity testing
cp -r "$TESTDATA" "$PRISTINE/"

RESTORE_DIR="$TEST_ROOT/restored"

run() {
    echo "→ soal $*"
    "$SOAL_BIN" "$@"
    echo
}

# ========== TEST 1: Basic setup ==========
echo "=== Test 1: Initialization and Vault Creation ==="
run init
run vault create photos          # encrypted by default
run vault create notes --no-encrypt
run vault list
echo "✓ Vaults created"

# ========== TEST 2: Add directory ==========
echo "=== Test 2: Adding a directory ==="
run add "$TESTDATA" --vault photos
run status --vault photos
echo "✓ Directory added"

# ========== TEST 3: Snapshots and commit history ==========
echo "=== Test 3: Snapshots and commit history ==="
run snapshot "Initial backup" --vault photos
run snapshot "After first import" --vault photos

# Capture the clean full-directory commit *before* modifying data on disk
CLEAN_HEAD=$( "$SOAL_BIN" status --vault photos | grep HEAD | awk '{print $2}' )

# Modify a file and add again (this creates a new tree for this operation)
echo "MODIFIED for version 2" >> "$TESTDATA/file-a.txt"
run add "$TESTDATA/file-a.txt" --vault photos --message "Updated file-a"
run snapshot "Version 2 of file-a" --vault photos

COMMITS=$(ls "$TEST_ROOT/.soal/vaults/photos/commits" | wc -l)
echo "Number of commits: $COMMITS"
[[ $COMMITS -ge 3 ]] || { echo "✗ Expected at least 3 commits"; exit 1; }
echo "✓ Multiple snapshots and history work"

# ========== TEST 4: Restore fidelity (using the clean directory commit) ==========
echo "=== Test 4: Restore and data fidelity ==="
rm -rf "$RESTORE_DIR"
mkdir -p "$RESTORE_DIR"
run restore "$CLEAN_HEAD" --vault photos --to "$RESTORE_DIR"

# The first add was of the whole $TESTDATA dir, so entries are under "original/..."
if diff -r "$PRISTINE/original" "$RESTORE_DIR/original"; then
    echo "✓ Restore produced identical data (bit-for-bit)"
else
    echo "✗ Restore data mismatch!"
    diff -r "$PRISTINE/original" "$RESTORE_DIR/original" || true
    exit 1
fi

# ========== TEST 5: Deduplication ==========
echo "=== Test 5: Deduplication ==="
CHUNK_COUNT=$(ls "$TEST_ROOT/.soal/vaults/photos/chunks" | wc -l)
echo "Chunks stored: $CHUNK_COUNT"
# We added several files but with one duplicate + small data → chunk count should be low
[[ $CHUNK_COUNT -le 5 ]] || { echo "✗ Too many chunks, dedup may not be working"; exit 1; }
echo "✓ Deduplication appears to be working"

# ========== TEST 6: Encryption at rest ==========
echo "=== Test 6: Encryption at rest ==="
# Pick a chunk from the encrypted vault
CHUNK_FILE=$(ls "$TEST_ROOT/.soal/vaults/photos/chunks/" | head -1)
CHUNK_PATH="$TEST_ROOT/.soal/vaults/photos/chunks/$CHUNK_FILE"

if grep -q "File A content" "$CHUNK_PATH" 2>/dev/null || strings "$CHUNK_PATH" 2>/dev/null | grep -q "File A"; then
    echo "✗ FAILURE: Plaintext visible in encrypted chunk!"
    exit 1
else
    echo "✓ No plaintext visible in encrypted chunks"
fi

# Check unencrypted vault
UNENC_CHUNK=$(ls "$TEST_ROOT/.soal/vaults/notes/chunks/" 2>/dev/null | head -1 || true)
if [[ -n "$UNENC_CHUNK" ]]; then
    if grep -q "File B" "$TEST_ROOT/.soal/vaults/notes/chunks/$UNENC_CHUNK" 2>/dev/null; then
        echo "✓ Unencrypted vault stores plaintext (expected)"
    fi
fi

# ========== TEST 7: Basic CLI help and errors ==========
echo "=== Test 7: CLI sanity ==="
"$SOAL_BIN" --help > /dev/null
"$SOAL_BIN" vault --help > /dev/null
echo "✓ CLI responds correctly"

echo
echo "=========================================="
echo "✅ All Phase 0 E2E tests PASSED"
echo "=========================================="
echo
echo "To run individual checks:"
echo "  cargo test"
echo "  ./scripts/test-phase0.sh"
echo
echo "For manual testing with isolation:"
echo "  export HOME=\$(mktemp -d)"
echo "  ./target/debug/soal ..."
