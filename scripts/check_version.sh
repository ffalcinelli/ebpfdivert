#!/bin/bash
# Exit on error
set -e

# Get the directory of this script
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# Extract version from include/ebpfdivert.h
CODE_VERSION=$(grep -oP '#define EBPFDIVERT_VERSION "\K[^"]+' "$REPO_DIR/include/ebpfdivert.h" 2>/dev/null || true)

if [ -z "$CODE_VERSION" ]; then
    # Fallback to sed if grep -P is not available
    CODE_VERSION=$(sed -n 's/.*#define EBPFDIVERT_VERSION "\(.*\)".*/\1/p' "$REPO_DIR/include/ebpfdivert.h")
fi

if [ -z "$CODE_VERSION" ]; then
    echo "Error: Could not extract EBPFDIVERT_VERSION from include/ebpfdivert.h"
    exit 1
fi

echo "Code version declared: $CODE_VERSION"

# Check if we are inside a git repository
if [ -d "$REPO_DIR/.git" ]; then
    # Check if the current commit has a tag
    if CURRENT_TAG=$(git -C "$REPO_DIR" describe --tags --exact-match 2>/dev/null); then
        # Current commit is tagged! They MUST be aligned.
        TAG_VERSION="${CURRENT_TAG#v}"
        echo "Current commit is tagged with: $CURRENT_TAG"
        if [ "$TAG_VERSION" != "$CODE_VERSION" ]; then
            echo "Error: Tag version ($TAG_VERSION) does not match code version ($CODE_VERSION)!"
            exit 1
        else
            echo "Success: Git tag and code version are aligned on this release commit ($CURRENT_TAG)."
        fi
    else
        # Current commit is not tagged. We will print the latest tag and code version.
        LATEST_TAG=$(git -C "$REPO_DIR" describe --tags --abbrev=0 2>/dev/null || true)
        if [ -n "$LATEST_TAG" ]; then
            TAG_VERSION="${LATEST_TAG#v}"
            echo "On untagged commit. Code version: $CODE_VERSION, Latest tag: $LATEST_TAG"
        else
            echo "On untagged commit. Code version: $CODE_VERSION (no git tags found)"
        fi
    fi
else
    echo "Not a git repository, skipping alignment check."
fi
