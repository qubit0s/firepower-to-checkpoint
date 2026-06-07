#!/usr/bin/env bash
# ===========================================================================
# 2_parse.sh -- convert a Cisco FTD `show running-config` into vars/*.yml
#
#   ./2_parse.sh /path/to/show-running-config.txt [--acls A,B]
#
# The config path is REQUIRED -- the script never falls back to the bundled
# demo, so you can't accidentally parse/apply the sample against a real mgmt.
# (To try the demo on purpose: ./2_parse.sh samples/ftd_running-config.txt)
# ===========================================================================
set -euo pipefail
cd "$(dirname "$0")"

if [ "$#" -lt 1 ] || [ -z "${1:-}" ]; then
  echo "ERROR: no config file given."
  echo "Usage: ./2_parse.sh /path/to/show-running-config.txt [--acls A,B]"
  echo "       (to test with the bundled demo: ./2_parse.sh samples/ftd_running-config.txt)"
  exit 1
fi
CONFIG="$1"
if [ ! -f "$CONFIG" ]; then
  echo "ERROR: config file not found: $CONFIG"
  echo "Usage: ./2_parse.sh /path/to/show-running-config.txt [--acls A,B]"
  exit 1
fi
if [ ! -x ".venv/bin/python" ]; then
  echo "ERROR: virtualenv missing. Run ./1_setup.sh first."
  exit 1
fi

# The parser prints a colored overview + a clear "what's auto-handled vs needs
# attention" verdict and the next step. Extra args pass through, e.g.:
#   ./2_parse.sh <config> --acls CSM_FW_ACL_,inside_access_in
#   ./2_parse.sh <config> --package "DC1-Policy"        # name the policy package
# (--package defaults to the FMC Access Control Policy name; override as above,
#  or per-ACL: --package "CSM_FW_ACL_=Edge,ACL_in=Inside")
.venv/bin/python parser/ftd_to_cp.py --config "$CONFIG" --out vars --reports reports "${@:2}"
