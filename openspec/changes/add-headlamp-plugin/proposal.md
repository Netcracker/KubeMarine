# Proposal

## Why

The `kubernetes-dashboard` plugin ships Kubernetes Dashboard v2.7.0, which is no longer actively developed; the Kubernetes SIG UI now recommends Headlamp as its successor. KubeMarine needs a supported web UI plugin so clusters can move off the legacy dashboard without losing UI access.

## What Changes

- Add a new out-of-box `headlamp` plugin (disabled by default) that installs a vendored Headlamp Helm chart (`v0.46.0`, as it latest currently) via KubeMarine's Helm plugin mechanism.
- New inventory section `plugins.headlamp` with `version`, `namespace`, `releaseName`, `hostname`, `headlampRegistry`, `debugRegistry`, `debugImage`, `values`, plus generic plugin properties (`install`, `installation`), validated by a JSON schema.
- Expose Headlamp through the installed ingress controllers: an `Ingress` for `nginx-ingress-controller` and/or an `HTTPRoute` on `default-external-gateway` for `envoy-gateway`.
- Hardened defaults: `restricted`-PSS-compatible security context, Linux node selector, resource requests and limits, node-shell pods in `kube-system`, and static plugins disabled. Users can override any of these through `values`.
- Registry resolution for the Headlamp image and the debug (node shell / pod debug) image, honoring `plugin_defaults`, `installation.registry`, and plugin-specific registries.
- Inventory validation that rejects `headlamp` and `kubernetes-dashboard` being installed with the same hostname. The default hostname `dashboard.{{ cluster_name }}` is shared on purpose, to make migration easy.
- A "Headlamp URL" line in the installation summary report.
- Compatibility map entries (Headlamp `v0.46.0`, alpine `3.24.2`) for all supported Kubernetes versions, plus support for upgrade patches (`upgrade_headlamp`, with `debugImage` treated as an image key that must be redefined on upgrade).
- `check_paas` additions: new test `237 Headlamp Availability`, plus Headlamp coverage in pods condition, default services configuration (image version), and health status checks.
- Fix in `default_services_health_status`: a plugin that is not installed now skips only that plugin instead of skipping all remaining plugins.
- Mark `kubernetes-dashboard` as deprecated in the docs and add a documented migration procedure to Headlamp. The `kubernetes-dashboard` plugin itself is unchanged; it is not removed and this change is not breaking.

## Capabilities

### New Capabilities
- `headlamp-plugin`: Installation, configuration, exposure, registry resolution, validation, upgrade, and reporting behavior of the Headlamp web UI plugin.
- `paas-check`: Post-installation PaaS checks (`check_paas`) that verify plugin availability and health. This change adds the Headlamp-related checks and fixes the plugin health-check iteration.

### Modified Capabilities
<!-- None: no specs exist yet under openspec/specs/. -->

## Impact

- **Code**: new `kubemarine/plugins/headlamp.py`; changes to `kubemarine/core/resources.py`, `kubemarine/core/summary.py`, `kubemarine/plugins/__init__.py`, `kubemarine/procedures/check_paas.py`, and `scripts/thirdparties/src/software/plugins.py`; `kubemarine.spec` hidden import.
- **Resources**: vendored chart `kubemarine/plugins/charts/headlamp-v0.46.0/` (with chart template tests); `defaults.yaml`, `globals.yaml`, compatibility maps, JSON schemas (`plugins/headlamp.json`, `plugins.json`, `migrate_kubemarine.json`), software upgrade patch lists.
- **Docs/examples/CI**: `docs/public/Installation.md` (plugin section, auth proxy, migration, and image tables), `docs/public/Kubecheck.md`, `examples/cluster.yaml/full-cluster.yaml`, `ci/default_cluster.yaml`, `ci/extended_cluster.yaml`.
- **Tests**: `test/unit/plugins/test_headlamp.py`, `test/unit/test_migrate_kubemarine.py`, `test/unit/tools/thirdparties/test_sync.py`.
- **Dependencies/artifacts**: new images `ghcr.io/headlamp-k8s/headlamp:v0.46.0` and `library/alpine:3.24.2` (alpine is shared with local-path-provisioner) for air-gapped mirrors. The chart is not downloaded automatically by the third-party sync tooling; it is vendored manually.
- **Compatibility**: additive. Existing inventories are unaffected because the plugin is `install: false` by default.
