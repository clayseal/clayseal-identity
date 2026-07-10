#!/usr/bin/env bash
# One-time developer setup for clay-seal-identity: create a virtualenv, install
# the package (client + server) with dev tooling, and run the test suite.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

PYTHON="${PYTHON:-python3.13}"

echo "==> Creating virtual environment (.venv) with $PYTHON"
"$PYTHON" -m venv .venv
# shellcheck disable=SC1091
source .venv/bin/activate

python -m pip install --upgrade pip

echo "==> Installing clayseal-identity[dev] (client + server + test/lint/type tooling)"
pip install -e ".[dev]"

echo "==> Running the test suite"
pytest backend/tests sdk/python/tests -q

echo ""
echo "Bootstrap complete. Activate the environment with:  source .venv/bin/activate"
echo "  clayseal-identity --help"
echo "  python examples/01_quickstart.py"
