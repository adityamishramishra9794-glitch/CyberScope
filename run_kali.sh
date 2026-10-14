#!/usr/bin/env bash
# CyberScope V4 launcher for Kali Linux / Debian-based systems.
set -e
cd "$(dirname "$0")/.."
if ! command -v python3 >/dev/null; then
  echo "python3 not found. Install with: sudo apt install python3 python3-venv python3-pip"; exit 1
fi
if [ ! -d .venv ]; then
  echo "Creating virtual environment..."
  python3 -m venv .venv
  . .venv/bin/activate
  pip install --upgrade pip
  pip install -r requirements.txt
else
  . .venv/bin/activate
fi
exec python main.py "$@"
