#!/usr/bin/env bash
# ==============================================================================
# Ether Release Preflight Check
# ==============================================================================
# Verifies codebase health, AST invariants, test suite, benchmark thresholds,
# wheel build, and bundled asset integrity before release.
set -euo pipefail

echo "========================================================"
echo "          Ether Release Preflight Sanity Check          "
echo "========================================================"

PYTHON_BIN="python3"
if [ -f ".venv/bin/python" ]; then
    PYTHON_BIN=".venv/bin/python"
fi

RUFF_BIN="ruff"
if [ -f ".venv/bin/ruff" ]; then
    RUFF_BIN=".venv/bin/ruff"
fi

PYTEST_BIN="pytest"
if [ -f ".venv/bin/pytest" ]; then
    PYTEST_BIN=".venv/bin/pytest"
fi

echo -e "\n[1/4] Running Mechanical Verification Suite (style, schema sync, invariants, regression)..."
bash scripts/verify.sh

echo -e "\n[2/4] Performance Limits & Benchmark Regression Guard..."
$PYTHON_BIN tests/benchmarks/runner.py --check

echo -e "\n[3/4] In-Tree AST Mutation Testing..."
$PYTHON_BIN tests/mutation/run_mutation_tests.py --target=canonicalize

echo -e "\n[4/4] Package Build & Asset Integrity Verification..."
rm -rf dist/ build/ *.egg-info
if command -v uv >/dev/null 2>&1; then
    uv build
else
    $PYTHON_BIN -m pip install --quiet build
    $PYTHON_BIN -m build
fi

$PYTHON_BIN -c "
import zipfile, glob, sys

wheels = glob.glob('dist/*.whl')
if not wheels:
    print('[-] Error: No wheel found in dist/')
    sys.exit(1)

wheel = wheels[0]
with zipfile.ZipFile(wheel, 'r') as z:
    names = set(z.namelist())

prefix = 'ether/assets/wordlists/'
required_assets = [
    prefix + 'common_dirs.txt.gz',
    prefix + 'subdomains_500.txt.gz',
    prefix + 'common_params.txt.gz',
    prefix + 'common_passwords.txt.gz',
    prefix + 'common_usernames.txt.gz',
    'tools/nmap/manifest.toml',
    'tools/nuclei/manifest.toml',
    'tools/ffuf/manifest.toml',
    'tools/http_probe/manifest.toml',
    'tools/dnspython/manifest.toml',
]

missing = [w for w in required_assets if w not in names]
if missing:
    print(f'[-] Error: Built wheel is missing required bundled assets: {missing}')
    sys.exit(1)

print(f'[+] Wheel verification passed: {wheel}')
print(f'[+] All {len(required_assets)} required bundled assets & tool manifests verified in wheel.')
"

echo -e "\n========================================================"
echo " ✓ PREFLIGHT SUCCESS: Ether is 100% ready for release!  "
echo "========================================================"
