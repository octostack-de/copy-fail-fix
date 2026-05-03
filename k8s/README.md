# CVE-2026-31431 (copy.fail) — Kubernetes mitigation

Runtime mitigation for the AF_ALG family on Kubernetes nodes. Parallel to `vm/playbook.yml` for standalone Ubuntu 24.04 VMs. Closes the exploit window without requiring a reboot or kernel upgrade.

## What it does

For every node in the current kubectl context, creates a one-shot Job that:

1. Writes `/etc/modprobe.d/disable-af_alg.conf` to block future loads of the AF_ALG family.
2. Attempts to unload `algif_aead`, `algif_hash`, `algif_skcipher`, `algif_rng`, `af_alg`.
3. Succeeds when `algif_aead` (the CVE module) is unloaded and the modprobe block is in place.

Family modules pinned by other processes — for example a long-lived `AF_ALG` socket holder (a hardware-security or RNG device plugin, an entropy daemon, etc.) keeping `algif_rng` open — are reported as a warning rather than a failure. They aren't the exploit path, and the modprobe block prevents `algif_aead` from being reloaded via `request_module()`.

Jobs are GC'd 5 minutes after completion (`ttlSecondsAfterFinished: 300`).

## Prerequisites

- `kubectl` configured against the target cluster.
- `envsubst` (from `gettext`; pre-installed on most Linux, `brew install gettext` on macOS).

## Apply

```sh
./k8s/apply.sh
```

The script:
1. Creates the `copy-fail-mitigation` namespace with PodSecurity labels set to `privileged` (needed because the pod runs `privileged: true` and `hostPID: true`).
2. Generates and applies one Job per node, pinned via `nodeName`.
3. Waits up to 120s per node and prints a per-node OK/FAILED summary.
4. Exits non-zero if any node failed.

## Verify

Job-level status:

```sh
kubectl -n copy-fail-mitigation get jobs
```

Runtime check (modules actually unloaded on each host):

```sh
kubectl get nodes -o name | xargs -I{} sh -c \
  'kubectl debug {} --image=busybox -i -q -- sh -c "lsmod | grep -E algif_\\|af_alg || echo CLEAN"'
```

Note: `../check-nodes.sh` (kernel-config probe) will still report `AT RISK` because the kernel **config** (`=m`) hasn't changed. The runtime check above is what confirms the mitigation is active. On nodes where the AF_ALG family is held by a long-lived consumer, the runtime check will list `algif_rng` and `af_alg` as still loaded — that's expected (see step 3 above) and not a regression.

## Re-run for new nodes

Safe to re-run `apply.sh` any time. Existing completed Jobs are unaffected; only newly-added nodes get fresh Jobs.

## Rollback

Deleting the workload does **not** remove the on-disk file. To fully revert on a node:

```sh
sudo rm /etc/modprobe.d/disable-af_alg.conf
sudo modprobe algif_aead   # only if you actually need it loaded again
```

To remove the workload:

```sh
kubectl delete -f k8s/namespace.yaml
```
