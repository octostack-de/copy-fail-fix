# CVE-2026-31431 (copy.fail) — kernel module mitigation

Detect and runtime-mitigate the `algif_aead` exposure exploited by `copy.fail` on Linux hosts built with `CONFIG_CRYPTO_USER_API_AEAD=m`. Closes the userspace exploit path without requiring a kernel patch or reboot. Works on standalone Ubuntu 22.04 / 24.04 VMs and on Kubernetes nodes.

## What it does

For each host, in two steps:

1. Writes `/etc/modprobe.d/disable-af_alg.conf` containing `install algif_aead /bin/false`. After this, the kernel's `request_module("algif_aead")` path — used when userspace runs `socket(AF_ALG); bind(..., type=aead, ...)` — executes `/bin/false`, and the `bind()` fails.
2. Runs `modprobe -r` on the AF_ALG family modules in dependency order (children before the `af_alg` parent).

The mitigation persists until the conf file is removed.

## Layout

| Path | Purpose |
|---|---|
| `check-nodes.sh` | Probe nodes in a kubectl context; classify each as AT RISK / MITIGATED / NOT AT RISK |
| `k8s/` | Kubernetes Job that applies the mitigation per node — see [k8s/README.md](k8s/README.md) |
| `vm/` | Ansible playbook for standalone Ubuntu 22.04 / 24.04 VMs |

## Quick start

Detect:

```sh
./check-nodes.sh                  # current kubectl context
./check-nodes.sh ctx1 ctx2 …      # explicit kubeconfig contexts
```

Mitigate Kubernetes nodes:

```sh
./k8s/apply.sh
```

Mitigate standalone Ubuntu 22.04 / 24.04 VMs:

```sh
cp vm/inventory.ini.example vm/inventory.ini   # then edit hostnames/IPs
ansible-playbook -i vm/inventory.ini vm/playbook.yml
```

## Scope and limitations

- **`=m` kernels only.** If `CONFIG_CRYPTO_USER_API_AEAD=y` (built-in), modprobe overrides do nothing — the affected code is in the kernel image and the node needs a patched kernel. `check-nodes.sh` flags those nodes explicitly.
- **CVE-specific success criterion.** A host is considered mitigated when `algif_aead` is unloaded *and* the modprobe block is in place. The other family modules (`algif_hash`, `algif_skcipher`, `algif_rng`, `af_alg`) may remain loaded if held by long-lived AF_ALG socket consumers — that does not reopen the CVE, since the block prevents `algif_aead` from being reloaded by `request_module()`.
- **Not a substitute for a patched kernel.** Once your distro ships a fix, upgrade and reboot; remove the conf file if you need any of these modules back.

## Requirements

- Detect / Kubernetes: `kubectl`, plus `envsubst` (from GNU `gettext`) for `k8s/apply.sh`.
- VMs: Ansible, with SSH to targets running Ubuntu 22.04 or 24.04.

## License

MIT — see [LICENSE](LICENSE).
