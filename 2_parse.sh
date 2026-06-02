#!/usr/bin/env bash
# ===========================================================================
# 2_parse.sh -- convert a Cisco FTD `show running-config` into vars/*.yml
#
#   ./2_parse.sh /path/to/show-running-config.txt
#   ./2_parse.sh                       # defaults to samples/ftd_running-config.txt
# ===========================================================================
set -euo pipefail
cd "$(dirname "$0")"

CONFIG="${1:-samples/ftd_running-config.txt}"
if [ ! -f "$CONFIG" ]; then
  echo "ERROR: config file not found: $CONFIG"
  echo "Usage: ./2_parse.sh /path/to/show-running-config.txt"
  exit 1
fi
if [ ! -x ".venv/bin/python" ]; then
  echo "ERROR: virtualenv missing. Run ./1_setup.sh first."
  exit 1
fi

# The parser prints a colored overview + a clear "what's auto-handled vs needs
# attention" verdict and the next step. Extra args pass through, e.g.:
#   ./2_parse.sh <config> --acls CSM_FW_ACL_,inside_access_in
.venv/bin/python parser/ftd_to_cp.py --config "$CONFIG" --out vars --reports reports "${@:2}"
