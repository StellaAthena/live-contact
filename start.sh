#!/bin/sh
# Start the local signer; set up its isolated Python environment on first use.
set -eu
cd "$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"

if [ ! -x .venv/bin/python ]; then
    python3 -m venv .venv
fi
if ! cmp -s requirements.txt .venv/live-contact-requirements.txt; then
    .venv/bin/python -m pip --isolated install --no-user --disable-pip-version-check -r requirements.txt
    cp requirements.txt .venv/live-contact-requirements.txt
fi
exec .venv/bin/python server.py "$@"
