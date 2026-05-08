#!/usr/bin/env bash
# Apply the CVE-2026-31431 (copy.fail) runtime mitigation as a DaemonSet.
# Unlike apply-jobs.sh, the DaemonSet auto-covers nodes that join the cluster
# later — no need to re-run for new nodes.
#
# Re-running is safe: kubectl apply is idempotent, and the init container's
# script writes the same modprobe.d block on every restart.
#
# Requires: kubectl.

set -euo pipefail

DIR=$(cd "$(dirname "$0")" && pwd)
NS=copy-fail-mitigation
DS=copy-fail-mitigation

kubectl apply -f "$DIR/namespace.yaml"
kubectl apply -f "$DIR/daemonset.yaml"

# Wait for the DaemonSet to roll out across all nodes. The status command
# blocks until every desired pod is Ready or the timeout expires; we don't
# fail the script here so the per-node summary below always prints.
kubectl -n "$NS" rollout status "ds/$DS" --timeout=180s || true

printf "\n  %-60s %s\n" "NODE" "RESULT"
fail=0
while IFS=$'\t' read -r pod node ready; do
  [ -n "$pod" ] || continue
  if [ "$ready" = "true" ]; then
    printf "  %-60s OK\n" "$node"
  else
    printf "  %-60s FAILED\n" "$node"
    kubectl -n "$NS" logs "$pod" -c mitigate --tail=20 2>/dev/null || true
    fail=1
  fi
done < <(kubectl -n "$NS" get pods \
           -l app.kubernetes.io/name=copy-fail-mitigation \
           -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.spec.nodeName}{"\t"}{.status.containerStatuses[?(@.name=="pause")].ready}{"\n"}{end}')
exit $fail
