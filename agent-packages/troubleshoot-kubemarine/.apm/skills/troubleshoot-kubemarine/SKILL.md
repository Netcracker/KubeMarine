---
name: troubleshoot-kubemarine
description: Diagnose and resolve Kubemarine installation, upgrade, and Kubernetes operational failures from artifacts attached to a ticket — KME error codes, kubectl/etcd logs, pipeline output, or cluster.yaml. Use when troubleshooting a kubemarine install/upgrade/add_node/remove_node procedure failure, an etcd issue, a Calico networking problem, a node NotReady status, a CoreDNS resolution failure, an ingress or webhook failure, or any Kubernetes generic operational issue in a KubeMarine-managed cluster.
---

## Scope

Assessment-focused troubleshooting for KubeMarine-managed Kubernetes clusters and the KubeMarine CLI tool itself,
worked exclusively from artifacts already attached to the ticket (error output, logs, `cluster.yaml`, pipeline
output). No live environment access is assumed — commands are never run against the cluster.

If the attached evidence is insufficient to reach a conclusion, the outcome is:
**"ask the requester to collect \<specific artifact\> and resubmit"** — not a live diagnostic step.

KubeMarine is a CLI tool that installs, upgrades, and maintains Kubernetes clusters on bare metal or VM nodes via
SSH. It operates on a `cluster.yaml` inventory and optional procedure YAML files.

---

## Main KubeMarine Procedures

| Procedure     | What it does                                          |
| ------------- | ----------------------------------------------------- |
| `install`     | Full cluster installation from `cluster.yaml`         |
| `add_node`    | Add one or more nodes to a running cluster            |
| `remove_node` | Remove nodes gracefully                               |
| `upgrade`     | Upgrade Kubernetes and cluster components             |
| `backup`      | Back up etcd and cluster state                        |
| `restore`     | Restore from backup                                   |
| `check_iaas`  | Pre-flight connectivity and infrastructure checks     |
| `check_paas`  | Post-install platform checks (kubecheck)              |

A failed task shows as `TASK FAILED <task.path>` followed by a `KME` error code.

---

## Evidence Sources

Work only from what is already attached. If a required artifact is missing, name it explicitly and ask the
requester to collect it — do not attempt to infer its content.

| Artifact to request / look for        | What to extract from it                                                 |
| ------------------------------------- | ----------------------------------------------------------------------- |
| Kubemarine stdout / pipeline output   | `TASK FAILED` line, KME code, traceback                                |
| `cluster.yaml`                        | Node roles, OS family, k8s version, registry, plugin config            |
| Procedure YAML                        | Target versions, tasks list, inventory overrides                        |
| `kubectl get nodes -o wide` output    | Node status, IP addresses, OS, k8s version                             |
| `kubectl describe node <name>` output | Conditions, events, kubelet version, kernel version                     |
| `kubectl get pods -A` / events        | Pod state, terminating pods, event messages                             |
| `kubelet` logs (journalctl or file)   | `NotReady` cause, PLEG errors, CRI failures                             |
| `etcd` pod logs / `etcd.yaml` manifest| Corruption panic, timeout, heartbeat warning, disk space errors         |
| Calico / CNI pod logs                 | BGP session failures, XDP errors, RBAC list/watch errors                |
| `kubeadm-config` ConfigMap dump       | Image repository, etcd extra args, controller-manager flags             |
| `check_iaas` / `check_paas` output   | Infrastructure and platform pre-flight check results                    |
| `/etc/kubemarine/kube_tasks/` archive | Post-failure cluster state dump (ask requester to tar and attach)       |

---

## Investigation Flow

**General rule**: every "check" below means "look in the attached artifacts". If the relevant artifact is not
attached, ask the requester to collect it and resubmit — do not attempt to infer or guess its content.

### KME error code present

Match the code to "Common Failure Modes / Kubemarine Errors" below. Each has a dedicated section in
`references/Troubleshooting.md` with the exact alert string and resolution steps.

### Upgrade procedure failed

1. Find the `TASK FAILED` line in the attached pipeline output to identify the failing task.
2. From the attached output, determine the cause: PDB violation, stuck-terminating pod, etcd manifest
   incompatibility (v1.28.3), image-repo mismatch, or node drain failure.
3. Do not recommend restarting the upgrade from the beginning — identify which minor-version step was already
   completed (from attached output or `cluster.yaml` version) and advise resuming from that point.
4. If attached evidence is insufficient to determine progress, ask the requester to attach the full pipeline
   output and the current `cluster.yaml`.

### Node `NotReady`

If kubelet logs are attached, look for PLEG health errors (`PLEG is not healthy`).
If `kubectl describe node` output is attached, check the kernel version — on Ubuntu 20.04, `5.4.0-132-generic`
is a known-bad kernel that causes this symptom.
If neither is attached, ask the requester to provide `kubectl describe node <name>` output and kubelet journal.

### Networking issue (pod-to-pod traffic or ingress)

From `cluster.yaml` or node info in attached artifacts:
- Multiple subnets visible? → MTU mismatch or Calico IP autodetection issue.
- Calico version 3.29.0 or 3.29.1 in `cluster.yaml` or pod image tag? → GC failures due to missing RBAC.
- Large cluster with many ingresses (visible from `kubectl get ingress`)? → ingress-nginx admission webhook timeout.

If none of the above artifacts are attached, ask the requester to attach `cluster.yaml` and Calico pod logs.

### etcd issue

From attached etcd pod logs or `etcd.yaml` manifest:
- `database space exceeded` / `no space` in logs → defrag needed.
- `request timed out` / heartbeat exceeded deadline in logs → disk I/O or election timeout tuning.
- Panic or corruption message in logs → `kubemarine restore` from backup or manual etcd restoration.

If etcd logs are not attached, ask the requester to collect them and resubmit.

### Incomplete or incorrectly ended installation

If no logs are attached, ask the requester to:
1. Attach the full kubemarine stdout from the failed run.
2. If that is unavailable, tar and attach `/etc/kubemarine/kube_tasks/` from any control-plane node — it
   contains the cluster state dump at the time of failure.

---

## Common Failure Modes

The table below is a locator index. For exact alert strings, root-cause detail, and engineer-executable resolution
steps, read the matching section of `references/Troubleshooting.md` using the lazy-read pattern:

1. `grep -n "^## " references/Troubleshooting.md` — list all section headers with line numbers.
2. Match the symptom to a header.
3. Read only that section with `offset`/`limit` (offset = header line, limit = lines until the next `## ` header).

### Kubemarine Errors (KME codes)

| Code / symptom                          | Summary                                                                        |
| --------------------------------------- | ------------------------------------------------------------------------------ |
| `KME0001` Unexpected exception          | Catch-all; advise requester to attach `check_iaas`/`check_paas` output        |
| `KME0002` Remote group exception        | A bash command on a node returned non-zero; identify the node from the traceback |
| `KME0002` Command timeout (2700 s)      | Hanging remote command; ask requester to check the node/hypervisor and SSH     |
| `KME0004` No control planes defined     | `cluster.yaml` has no node with the `control-plane` role — visible in attached file |
| `KME0005` Not sudoers                   | Connection user lacks passwordless sudo; visible from the error message        |
| `KME0006` Node accessibility            | Node offline or SSH unreachable; ask requester to verify address and SSH daemon |
| `KME0008` Invalid Kubernetes version    | Version not in the allowed list; visible from the error message                |
| `KME0009` Plugin config redefined       | Key in `cluster.yaml` plugin section missing in procedure YAML — compare files |
| `KME0010` Package associations redefined| Package associations in `cluster.yaml` missing in procedure YAML — compare files |
| `KME0011` Third-party config redefined  | Third-party key in `cluster.yaml` missing in procedure YAML — compare files   |
| `KME0012` OS family incompatibility     | Nodes have mixed or unsupported OS families; visible from `cluster.yaml`       |
| `KME0013` containerd `sandbox_image`    | `sandbox_image` key in `cluster.yaml` missing in procedure YAML — compare files |
| `KME0014` Invalid Helm chart URL        | URL returns unexpected content type; ask requester to verify URL and auth      |

### Kubernetes Generic Issues

| Symptom                                          | Resolution to recommend to requester                                    |
| ------------------------------------------------ | ----------------------------------------------------------------------- |
| CoreDNS high latency                             | Scale CoreDNS replicas; add anti-affinity rules                         |
| Terminating namespace / CR stuck                 | Restart the managing controller; if unavailable, manually remove finalizers |
| Packet loss across subnets                       | Reduce Calico `veth_mtu` by 20 bytes relative to node MTU              |
| `kubectl apply` → "annotations: Too long"        | Use `kubectl create` for this resource                                  |
| kube-apiserver 429 throttling                    | Increase `--max-requests-inflight` / `--max-mutating-requests-inflight` in manifest and `kubeadm-config` |
| Long node recovery after offline (> 5 min)       | Tune `nodeStatusUpdateFrequency`, `node-monitor-grace-period`, `pod-eviction-timeout` in `cluster.yaml` |
| kube-controller-manager GC sync failure          | Increase CPU/memory on control-plane nodes, or reduce kube-apiserver load |
| `etcd: database space exceeded`                  | Run `etcdctl defrag` on each member sequentially (not simultaneously)   |
| `etcdctl defrag` deadline exceeded               | Re-run with `--command-timeout=30s` or higher                           |
| etcd request timed out / heartbeat missed        | Tune `--heartbeat-interval`, `--election-timeout` in `etcd.yaml`; stagger `--snapshot-count` across nodes |
| etcd database corruption / pods won't start      | Restore with `kubemarine restore` from backup, or manual etcd restoration from snapshot |
| HTTPS ingress TLS cipher not supported           | Add the required cipher in an annotation on the `Ingress` resource      |
| Garbage collector not initializing (quota empty) | Restore broken converter webhook, or delete the CRD causing the failure |
| Pods stuck `Terminating` (RHEL/CentOS 7.x)      | Add `fs.may_detach_mounts=1` to `/etc/sysctl.conf` and apply with `sysctl -p` |
| Random 504 on ingresses                          | Add `podSubnet` and `serviceSubnet` to IaaS security group / allowed address pairs |
| Nodes `NotReady` periodically (Ubuntu 20.04)     | Upgrade kernel from `5.4.0-132-generic` to `5.4.0-135-generic`         |
| Long image pull / pods stuck `ContainerCreating` | Set `--serialize-image-pulls=false` on kubelet (not for Docker < 1.9 or aufs) |
| No pod-to-pod (multi-interface nodes)            | Set `IP_AUTODETECTION_METHOD: interface=<correct-iface>` in `cluster.yaml` Calico config |
| No pod-to-pod (multiple IPs, different CIDR)     | Set `IP_AUTODETECTION_METHOD: kubernetes-internal-ip` (requires Calico ≥ 3.22.4 / 3.24.0) |
| Ingress creation fails with webhook timeout      | Increase `timeoutSeconds` in `ValidatingWebhookConfiguration`, or add `--disable-full-test` |
| vIP unreachable after installation               | GARP is disabled in the IaaS layer — ask requester to contact infrastructure team to enable it |
| CoreDNS NXDOMAIN for short names                | Use FQDN instead of short name; or install `bind-tools` in the pod     |
| CoreDNS timeout from `hostNetwork` pods          | Allow UDP/53 traffic from node network to pod network in IaaS security group |
| Audit daemon → "No buffer space available"       | Adjust auditd buffer size or disable the auditd daemon                  |
| Calico high CPU / XDP log flood                  | Set `FELIX_XDPENABLED: 'false'` in `cluster.yaml` Calico env and reapply |
| Calico 3.29.0–3.29.1 GC failures               | Apply RBAC for `tier.[global]networkpolicies.projectcalico.org` (see references); or upgrade Calico |

### Kubemarine-specific Issues

| Symptom                                              | Resolution to recommend to requester                                     |
| ---------------------------------------------------- | ------------------------------------------------------------------------ |
| Docker run → "Operation not permitted"               | Upgrade Docker to ≥ 1.13.1-109, or run container with `--privileged`    |
| Upgrade procedure failed, incomplete                 | Identify last successful step from attached output; resume from that point with updated `cluster.yaml` |
| Drain fails due to PDB violation                     | Use `disable-eviction` option (k8s ≥ 1.18), or temporarily reduce PDB `minAvailable` |
| Drain fails — pod stuck `Terminating`               | Force-delete the pod with `--grace-period=0 --force`; or reboot the node; then retry upgrade |
| etcd customizations lost after upgrade               | Before next upgrade: ensure customizations exist in both `etcd.yaml` and `kubeadm-config` ConfigMap |
| Kubernetes image repository unchanged after upgrade  | Manually update `imageRepository` in `kubeadm-config` ConfigMap and `cluster.yaml`; update CRI config |
| GC fails to reclaim disk (`DiskPressure`)            | Move `/var/lib/docker` to a dedicated disk; set `image-gc-high-threshold` below 85% |
| Upgrade to v1.28.3 fails at ETCD step               | Remove incompatible fields (`successThreshold`, `terminationMessage*`, `dnsPolicy`, `restartPolicy`) from `etcd.yaml` on each control-plane, then retry |
| Excessive `auditd` messages after cluster update     | Remove Docker-related watch rules from `/etc/audit/rules.d/predefined.rules`; restart auditd |
| Ubuntu cloud-init conflicts with installation        | Wait ~10 min after OS install and verify `cloud-init status` is done before running kubemarine |
| Installation ended incorrectly, no stdout available  | Ask requester to tar and attach `/etc/kubemarine/kube_tasks/` from a control-plane node |
| `kubectl logs`/`exec` → TLS internal error          | Approve pending kubelet server CSR — see the Hardening guide in references |
| OpenSSH unavailable on CentOS 9 (OpenSSL mismatch)  | Add `openssh-server` to `services.packages.upgrade` in `cluster.yaml` before next run |
| Packet loss between nodes in different subnets       | Move high-load pods to same-subnet nodes, or consolidate all cluster nodes into a single subnet |
| GitLab CI job log > 4 MB                            | Increase `output_limit` in GitLab Runner `config.toml`                  |

---

## Recommendation Discipline

- Always cite which attached artifact triggered the diagnosis and how the proposed fix addresses the observed evidence.
- Phrase the resolution as steps for the requester to execute — not as commands the AI runs.
- Ask for additional artifacts before recommending any destructive action (etcd restore, force-delete, CRD removal).
- For upgrade failures, always determine the current state from attached evidence before recommending next steps —
  never advise restarting from scratch without confirming what succeeded.
- Recovery verification: tell the requester what to look for after applying the fix (e.g. "rerun the failing
  kubemarine task and attach the new output", "verify node status with `kubectl get nodes`").

---

## Forbidden Actions

- Do not run or suggest running commands against the cluster directly.
- Do not recommend `--force-new-cluster` on a healthy etcd member.
- Do not recommend deleting etcd data without a backup confirmed in the attached artifacts.
- Do not recommend disabling `--serialize-image-pulls` on nodes with Docker < 1.9 or `aufs` storage.
- Do not recommend manually removing CRD finalizers as a first step — recommend controller restart first.
- Do not declare the cluster irreparable from etcd logs alone — ask the requester to confirm whether a backup
  snapshot exists before recommending restoration.
