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

# Colored completion banner (plain text if not a TTY)
if [ -t 1 ]; then G="\033[1;32m"; B="\033[1m"; N="\033[0m"; else G=""; B=""; N=""; fi
printf "\n${G}%s${N}\n" "✔ Setup complete."

cat <<DONE

${B}Next steps:${N}
  a) Edit inventory/hosts.ini   -> mgmt host + ONE auth block:
                                   Smart-1 Cloud (api key + cloud id) or
                                   on-prem (api key, or user/password)
  b) Parse your config          -> ./2_parse.sh /path/to/show-running-config.txt
       then review              -> vars/*.yml  and  reports/parse_summary.md
  c) Apply                      -> ./3_apply.sh            (all stages, one session)
                                   ./3_apply.sh objects    (one stage)
                                   ./3_apply.sh objects -C (dry-run / check mode)

(No need to activate the virtualenv manually -- 2_parse.sh and 3_apply.sh use it.)
DONE
