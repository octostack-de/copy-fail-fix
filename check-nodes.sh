#!/usr/bin/env bash
# Check Kubernetes nodes for CVE-2026-31431 (copy.fail) exposure.
#
# A node is unaffected if its running kernel was built without
# CONFIG_CRYPTO_USER_API_AEAD (the algif_aead userspace AEAD interface).
# Otherwise, the node is at risk and needs a patched kernel.
#
# The probe runs in an ephemeral `kubectl debug` pod that mounts the host
# filesystem at /host, so SSH access to the nodes is not required.
#
# Usage:
#   ./check-nodes.sh                          # checks the current kubectl context
#   ./check-nodes.sh <context> [context ...]  # checks each named context in turn
#
# Uses your existing $KUBECONFIG / ~/.kube/config; does not take kubeconfig paths.

set -euo pipefail

PROBE='
if [ -r /host/proc/config.gz ]; then
  cfg=$(zcat /host/proc/config.gz | grep CRYPTO_USER_API_AEAD || true)
elif [ -r "/host/boot/config-$(cat /host/proc/sys/kernel/osrelease)" ]; then
  cfg=$(grep CRYPTO_USER_API_AEAD "/host/boot/config-$(cat /host/proc/sys/kernel/osrelease)" || true)
else
  cfg=NO_CONFIG_FOUND
fi
[ -n "$cfg" ] || cfg=NO_CONFIG_FOUND
echo "CONFIG=$cfg"

if [ -d /host/sys/module/algif_aead ]; then
  echo "LOADED=YES"
else
  echo "LOADED=NO"
fi

if [ -r /host/etc/modprobe.d/disable-af_alg.conf ] && \
   grep -q "install algif_aead /bin/false" /host/etc/modprobe.d/disable-af_alg.conf 2>/dev/null; then
  echo "BLOCKED=YES"
else
  echo "BLOCKED=NO"
fi
'

verdict() {
  local out="$1" cfg loaded blocked
  cfg=$(printf '%s\n'    "$out" | sed -n 's/^CONFIG=//p'  | head -1)
  loaded=$(printf '%s\n' "$out" | sed -n 's/^LOADED=//p'  | head -1)
  blocked=$(printf '%s\n' "$out" | sed -n 's/^BLOCKED=//p' | head -1)

  case "$cfg" in
    *"CONFIG_CRYPTO_USER_API_AEAD=y"*)
      echo "AT RISK (built-in, needs patched kernel)" ;;
    *"CONFIG_CRYPTO_USER_API_AEAD is not set"*)
      echo "NOT AT RISK (config disabled)" ;;
    *"CONFIG_CRYPTO_USER_API_AEAD=m"*)
      if [ "$loaded" = "YES" ]; then
        echo "AT RISK (=m, module currently loaded)"
      elif [ "$blocked" = "YES" ]; then
        echo "MITIGATED (=m, unloaded and blocked)"
      else
        echo "AT RISK (=m, not loaded but loadable — recommend blocking)"
      fi ;;
    *NO_CONFIG_FOUND*)
      echo "UNKNOWN (no kernel config readable on host)" ;;
    *)
      echo "UNKNOWN" ;;
  esac
}

check_cluster() {
  # Optional arg: a context name. Empty = use whatever current-context is.
  local ctx="${1:-}"
  local k=(kubectl)
  if [ -n "$ctx" ]; then
    k+=(--context "$ctx")
  else
    ctx=$(kubectl config current-context 2>/dev/null || echo "?")
  fi

  printf "\n== %s ==\n" "$ctx"
  printf "  %-60s %-45s %-22s %s\n" "NODE" "OS-IMAGE" "KERNEL" "VERDICT"

  while read -r node; do
    [ -n "$node" ] || continue
    local os kernel out
    os=$("${k[@]}"   get node "$node" -o jsonpath='{.status.nodeInfo.osImage}')
    kernel=$("${k[@]}" get node "$node" -o jsonpath='{.status.nodeInfo.kernelVersion}')
    out=$("${k[@]}" debug "node/$node" --image=busybox --profile=general -i -q \
            -- sh -c "$PROBE" </dev/null 2>/dev/null || true)
    printf "  %-60s %-45s %-22s %s\n" "$node" "$os" "$kernel" "$(verdict "$out")"
  done < <("${k[@]}" get nodes -o name | sed 's|^node/||')

  # Cleanup any leftover node-debugger-* pods we created.
  "${k[@]}" get pods -A --no-headers 2>/dev/null \
    | awk '/node-debugger-/{print $1, $2}' \
    | while read -r ns p; do
        "${k[@]}" -n "$ns" delete pod "$p" --wait=false >/dev/null 2>&1 || true
      done
}

if [ $# -eq 0 ]; then
  check_cluster ""
else
  for ctx in "$@"; do
    check_cluster "$ctx"
  done
fi
