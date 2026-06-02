#!/usr/bin/env bash
# ===========================================================================
# 3_apply.sh -- run the migration playbook(s) against Smart-1 Cloud.
#
#   ./3_apply.sh                 # all stages, single session (site.yml)
#   ./3_apply.sh objects         # one stage: objects | object-groups | services | policy | nat
#   ./3_apply.sh objects -C      # dry-run (check mode); any extra args pass through
#   ./3_apply.sh undo            # DELETE migrated items (state=absent); --tags to scope
# ===========================================================================
set -euo pipefail
cd "$(dirname "$0")"

if [ ! -x ".venv/bin/ansible-playbook" ]; then
  echo "ERROR: virtualenv missing. Run ./1_setup.sh first."
  exit 1
fi

STAGE="${1:-site}"
shift || true
# Map friendly stage names to the numbered playbook files.
case "$STAGE" in
  objects)               PB="playbooks/1_objects.yml" ;;
  object-groups|groups)  PB="playbooks/2_object-groups.yml" ;;
  services)              PB="playbooks/3_services.yml" ;;
  policy)                PB="playbooks/4_policy.yml" ;;
  nat)                   PB="playbooks/5_nat.yml" ;;
  site|all)              PB="playbooks/site.yml" ;;
  undo)                  PB="playbooks/undo.yml" ;;
  *)                     PB="playbooks/${STAGE}.yml" ;;   # also accept exact filename
esac
if [ ! -f "$PB" ]; then
  echo "ERROR: unknown stage '$STAGE'. Valid: objects | object-groups | services | policy | nat | site | undo"
  exit 1
fi

exec .venv/bin/ansible-playbook "$PB" "$@"
