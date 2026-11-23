# Design

## Context

See proposal.md for motivation, and the `headlamp-plugin` and `paas-check` specs for the behavioral contract.

KubeMarine already supports two ways of installing out-of-box plugins: rendering manifests (for example `kubernetes-dashboard`, `local-path-provisioner`) and installing Helm charts vendored under `kubemarine/plugins/charts/` (for example `envoy-gateway`), using `plugins.apply_helm`. Plugin versions are resolved per Kubernetes version from `compatibility/internal/plugins.yaml` and `kubernetes_versions.yaml`. The `scripts/thirdparties` tooling keeps those maps in sync. Ingress can be provided by `nginx-ingress-controller`, `envoy-gateway`, or both at once.

## Goals / Non-Goals

**Goals:**
- Offer a supported web UI that can replace `kubernetes-dashboard` with minimal inventory changes.
- Reuse the existing Helm plugin mechanism instead of maintaining a custom manifest pipeline.
- Work in air-gapped environments using the standard registry overrides.
- Make Headlamp observable in `check_paas` on the same level as the legacy dashboard.

**Non-Goals:**
- Removing or changing the `kubernetes-dashboard` plugin. It is only marked deprecated in the docs.
- Automatic migration from `kubernetes-dashboard` to Headlamp. The migration is a documented manual procedure.
- Installing or configuring authentication (OIDC, auth proxy). The chart supports it through `values`, and the docs describe an external auth proxy.
- Automatic download of the Headlamp chart by the third-party sync tooling.

## Decisions

### Install from a vendored upstream Helm chart
The upstream Headlamp chart `v0.46.0` is vendored under `kubemarine/plugins/charts/headlamp-<version>/` and installed with `plugins.apply_helm` (`take_ownership: True`). The chart's own template tests (`tests/test.sh`, `test_cases/`, `expected_templates/`) and `update-version.sh` are kept to ease future upgrades.
- *Alternative*: render static manifests like `kubernetes-dashboard`. This was rejected because Headlamp's upstream distribution is Helm-first, and the chart already covers Ingress, HTTPRoute, PDB, OIDC, and security options that would otherwise have to be reimplemented.
- *Alternative*: pull the chart from a remote repository at install time. This was rejected because it does not work in air-gapped clusters.

### KubeMarine defaults merged under user `values`
`apply_headlamp_chart` builds a values dict (image registry, debug images, node shell namespace, static plugins off, restricted security context, Linux nodeSelector, resources, Ingress/HTTPRoute) and then merges `plugins.headlamp.values` over it with `default_merger`. As a result, lists are replaced and dicts are deep-merged. The effective values are dumped to `headlamp-values.yaml` for troubleshooting.
- *Rationale*: users get safe defaults but can override any chart value. List replacement makes the auth proxy case (replacing `ingress.hosts`) predictable.

### Expose according to the installed ingress controllers
An Ingress is added when nginx is installed, and an HTTPRoute (parentRef `default-external-gateway` in the envoy-gateway namespace) when envoy-gateway is installed. When both are installed, the Ingress gets the `gateway-api-converter.netcracker.com/ignore: "true"` annotation so the converter does not produce a duplicate HTTPRoute.
- *Alternative*: a single user-selected exposure mode. This was rejected to stay consistent with how other KubeMarine plugins follow the installed controllers.

### Default hostname shared with kubernetes-dashboard plus conflict validation
The default `hostname` is `dashboard.{{ cluster_name }}`, so a migrated cluster keeps its UI URL. To prevent two routes from silently claiming the same host, a FULL-stage enrichment step (`headlamp.verify_inventory`) fails when both plugins are installed with equal hostnames.
- *Alternative*: a distinct default (`headlamp.{{ cluster_name }}`). This was rejected because it forces URL changes during migration. CI inventories use `headlamp.{{ cluster_name }}` because both plugins are enabled there.

### Two images with layered registry resolution
The Headlamp image defaults to `ghcr.io` (where upstream publishes it). The debug image is `library/alpine:<alpine-version>` with no registry prefix, which means docker.io. Each image is resolved in this order: its specific key (`headlampRegistry` or `debugRegistry`), then `installation.registry` (which already includes the `plugin_defaults` enrichment), then the default. Separate keys are needed because the two images come from different public registries.
- The alpine version is tracked per Kubernetes version as `alpine-version` in the plugin compatibility map, and is shared with local-path-provisioner. The thirdparty sync tooling validates it as an extra image.

### Image version derived from Chart.yaml
`get_image_version` reads `appVersion` from the vendored `Chart.yaml` and returns `v<appVersion>`, which the chart uses as its default tag. `check_paas` uses it to validate the running image, and the sync tooling calls it to verify that the chart is vendored.
- *Alternative*: store the image version separately in the compatibility map. This was rejected because it duplicates the chart's source of truth.

### Hardened security context, node shell in kube-system
Pods run as UID 100 and GID 101 (the upstream image user) under a `restricted`-compatible context, so the Headlamp namespace can rely on the cluster's default PSS. Node shell pods must be privileged, so they default to `kube-system`, which already allows privileged pods.

### Upgrade support via existing patch mechanism
`headlamp: []` is added to the software upgrade patch lists. `debugImage` is added to the image-sensitive keys in `verify_image_redefined`, so upgrades require an explicit redefinition when the user pinned it. The `version` key was already covered.

### check_paas integration
New test 237 mirrors the dashboard check but probes both the Service (ClusterIP, IPv6-aware) and the HTTPS ingress endpoint using `curl --resolve` to the control-plane internal address. The Headlamp namespace and Deployment are added to the pods condition, configuration, and health checks. While adding Headlamp, a latent bug was fixed: `break` became `continue` in `default_services_health_status`, because `break` stopped evaluating all later plugins once one plugin was not installed.

## Risks / Trade-offs

- [Chart vendored manually; sync tooling only checks it exists] → `get_image_version` raises a clear error naming the expected path, and `update-version.sh` and the chart tests document the upgrade procedure.
- [Test 237 always probes HTTPS on 443; with envoy-gateway only and no certificate, Headlamp is served over HTTP] → `curl -L -k` follows redirects and ignores certificate validity, but an HTTP-only listener may still fail the probe. Users may see a false failure in that configuration (see Open Questions).
- [Users overriding list values (for example `ingress.hosts`) must specify them completely] → Documented in Installation.md and covered by a unit test for the auth proxy case.
- [Node shell pods are privileged] → They are confined to `kube-system` by default; the docs warn about changing `nodeShellNamespace`.
- [Equal default hostname with dashboard] → Validation fails fast with an actionable message.
- [Health check `break`→`continue` fix can surface previously hidden failures for later plugins] → This is the intended behavior.

## Migration Plan

Additive change: no action is needed for existing clusters. To migrate from kubernetes-dashboard, follow "Dashboard migration to Headlamp" in Installation.md:
1. Patch the dashboard Ingress or HTTPRoute hostname to a dummy value (for example `disable.com`), so the hostnames do not conflict.
2. Disable `kubernetes-dashboard`, enable `headlamp` (optionally with auth proxy backends in `values`), and run `install --tasks deploy.plugins`.
3. If you use an auth proxy, deploy it into the Headlamp namespace.
4. Verify that the UI and login work, then remove the `kubernetes-dashboard` namespace.

Rollback (before removing the namespace): patch the Headlamp Ingress or HTTPRoute hostname to a dummy value, and patch the dashboard hostname back.

## Open Questions

- Should test 237 select HTTP vs HTTPS using the same rule as the summary URL (`get_url`), so that envoy-only clusters without a certificate are probed correctly? Answering this does not change the plugin contract and can be handled as a follow-up.
