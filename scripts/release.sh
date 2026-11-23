#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# Ether Release Script (Solo Developer Automation)
#
# Usage:
#   ./scripts/release.sh <version>
# Example:
#   ./scripts/release.sh 0.2.0
# ==============================================================================

NEW_VERSION="${1:-}"
if [ -z "$NEW_VERSION" ]; then
    echo "[-] Error: Missing version argument."
    echo "Usage: $0 <version> (e.g. $0 0.2.0)"
    exit 1
fi

# 1. Cleanliness check
if [ -n "$(git status --porcelain)" ]; then
    echo "[-] Error: Working tree has uncommitted changes. Please commit or stash first."
    exit 1
fi

CURRENT_BRANCH="$(git rev-parse --abbrev-ref HEAD)"
if [ "$CURRENT_BRANCH" != "main" ]; then
    echo "[!] Warning: Current branch is '$CURRENT_BRANCH'."
    echo "    Releases should ideally be cut directly from 'main'."
    read -p "    Continue on '$CURRENT_BRANCH'? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Aborted."
        exit 1
    fi
fi

# 2. Release preflight checks
echo "[*] Step 1/4: Running release preflight verification..."
./scripts/release-check.sh

# 3. Bump version in pyproject.toml and .release-please-manifest.json
echo "[*] Step 2/4: Updating version to $NEW_VERSION..."
sed -i "s/^version = \".*\"/version = \"$NEW_VERSION\"/" pyproject.toml

if [ -f .release-please-manifest.json ]; then
    python3 -c "
import json
with open('.release-please-manifest.json', 'r') as f:
    d = json.load(f)
d['.'] = '$NEW_VERSION'
with open('.release-please-manifest.json', 'w') as f:
    json.dump(d, f, indent=2)
"
fi

# 4. Commit and Tag
echo "[*] Step 3/4: Committing version bump and creating git tag v$NEW_VERSION..."
git add pyproject.toml .release-please-manifest.json
git commit -m "chore(release): bump version to $NEW_VERSION"
git tag -a "v$NEW_VERSION" -m "Release v$NEW_VERSION"

# 5. Push instructions
echo "[+] Step 4/4: Ready to publish!"
echo "Run the following command to push and trigger the unified PyPI + Docker release:"
echo "  git push origin $CURRENT_BRANCH && git push origin v$NEW_VERSION"
