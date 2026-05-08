#!/usr/bin/env bash
# Apply the CVE-2026-31431 (copy.fail) runtime mitigation to every node in
# the current kubectl context. Generates one Job per node, waits for each,
# and reports a per-node OK/FAILED summary.
#
# Re-running is safe: completed Jobs vanish after ttlSecondsAfterFinished
# (5 min); new nodes get fresh Jobs. Failed nodes can be retried by
# deleting the failed Job and re-running this script.
#
# Requires: kubectl, envsubst (from gettext).

set -euo pipefail

DIR=$(cd "$(dirname "$0")" && pwd)
NS=copy-fail-mitigation

command -v envsubst >/dev/null || { echo "envsubst not found (install gettext)"; exit 1; }

kubectl apply -f "$DIR/namespace.yaml"

NODES=$(kubectl get nodes -o name | sed 's|^node/||')
[ -n "$NODES" ] || { echo "no nodes found"; exit 1; }

# Strip the Gardener "shoot--<project>--" prefix from node names so synthesized
# Job names stay short and readable; the substitution is a no-op on clusters
# whose node names don't start with that prefix.
job_for_node() { printf 'copy-fail-mitigation--%s' "${1#shoot--*--}"; }

for node in $NODES; do
  JOB_NAME=$(job_for_node "$node") NODE_NAME=$node \
    envsubst '${NODE_NAME} ${JOB_NAME}' < "$DIR/job.yaml" | kubectl apply -f -
done

printf "\n  %-60s %s\n" "NODE" "RESULT"
fail=0
for node in $NODES; do
  job=$(job_for_node "$node")
  if kubectl -n "$NS" wait --for=condition=Complete "job/$job" --timeout=120s >/dev/null 2>&1; then
    printf "  %-60s OK\n" "$node"
  else
    printf "  %-60s FAILED\n" "$node"
    kubectl -n "$NS" logs "job/$job" --tail=20 2>/dev/null || true
    fail=1
  fi
done
exit $fail
