#!/usr/bin/env bash
# ===========================================================================
# 1_setup.sh -- one-time setup. Creates a local virtualenv, installs the Python
# parser dependencies + Ansible, and installs the check_point.mgmt collection.
# Safe to re-run.
#
#   ./1_setup.sh
# ===========================================================================
set -euo pipefail
cd "$(dirname "$0")"

PY="${PYTHON:-python3}"
VENV=".venv"

echo "==> 1/4  Creating virtualenv ($VENV)"
"$PY" -m venv --clear "$VENV"
# shellcheck disable=SC1091
source "$VENV/bin/activate"
pip install --quiet --upgrade pip

echo "==> 2/4  Installing Python dependencies (ciscoconfparse2, PyYAML, ansible-dev-tools)"
pip install --quiet -r requirements.txt

echo "==> 3/4  Installing the check_point.mgmt Ansible collection"
ansible-galaxy collection install -r requirements.yml -p ./collections

echo "==> 4/4  Finalising"
chmod +x 2_parse.sh 3_apply.sh 2>/dev/null || true
echo "    edit inventory/hosts.ini with your Smart-1 Cloud details (next step)"

cat <<'DONE'

Setup complete.

Next steps:
  3) Edit inventory/hosts.ini   -> tenant host, API key, cloud management id
  4) Parse your config          -> ./2_parse.sh /path/to/show-running-config.txt
       then review              -> vars/*.yml  and  vars/_review_unsupported.yml
  5) Apply                      -> ./3_apply.sh            (all stages)
                                   ./3_apply.sh objects    (one stage)
                                   ./3_apply.sh objects -C (dry-run / check mode)

(No need to activate the virtualenv manually -- 2_parse.sh and 3_apply.sh use it.)
DONE
