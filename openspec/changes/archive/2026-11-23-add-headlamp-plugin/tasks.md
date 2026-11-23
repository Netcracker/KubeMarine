# Tasks

## 1. Chart and compatibility data

- [x] 1.1 Vendor upstream Headlamp chart `v0.46.0` under `kubemarine/plugins/charts/headlamp-v0.46.0/` with its template tests and `update-version.sh`; verify `Chart.yaml` has `appVersion: 0.46.0`
- [x] 1.2 Add `headlamp` (`version: v0.46.0`, `alpine-version: 3.24.2`) to `compatibility/internal/plugins.yaml` and `headlamp: v0.46.0` to `kubernetes_versions.yaml` for every supported Kubernetes version; verify with `test_sync.py`
- [x] 1.3 Add the `headlamp` entry to `globals.yaml` (no manifests, requirements link to GitHub releases); verify the sync tooling accepts it (`test_sync.py` expected software includes `headlamp`)
- [x] 1.4 Extend `scripts/thirdparties/src/software/plugins.py` to check that the chart is vendored (`headlamp.get_image_version`), fill `alpine-version`, and validate `alpine` as an extra image; verify `test_sync.py` extra-image tests pass for both `headlamp` and `local-path-provisioner`

## 2. Inventory model and validation

- [x] 2.1 Add `plugins/headlamp.json` schema and reference it from `definitions/plugins.json` and `migrate_kubemarine.json`; verify that unknown properties are rejected by inventory validation
- [x] 2.2 Add `plugins.headlamp` defaults to `defaults.yaml` (install false, namespace/releaseName `headlamp`, hostname `dashboard.{{ cluster_name }}`, registries, `debugImage`, priority 3, procedures: apply chart, expect deployment and pods, schedule summary); verify with `RegistryTest.test_default_registries` and `HostnameTest.test_default_hostname`
- [x] 2.3 Implement `headlamp.verify_inventory` (FULL enrichment) that rejects an equal hostname when both `headlamp` and `kubernetes-dashboard` are installed, and register it in `core/resources.py`; verify with `HostnameTest.test_same_hostname_with_dashboard`, `test_different_hostname_with_dashboard`, and `test_same_hostname_dashboard_not_installed`
- [x] 2.4 Document `plugins.headlamp` in `docs/public/Installation.md` (parameters, hostname note, exposure, registries, PSS, node shell) and add an example to `examples/cluster.yaml/full-cluster.yaml`; verify that the TOC links resolve

## 3. Chart installation

- [x] 3.1 Implement `apply_headlamp_chart`: registry resolution, debug image, node shell in `kube-system`, static plugins disabled, restricted security context, nodeSelector, resources; verify with all `RegistryTest` cases
- [x] 3.2 Add Ingress (nginx, TLS, converter-ignore annotation) and HTTPRoute (`default-external-gateway`) based on the installed ingress plugins; verify with `HostnameTest.test_default_hostname`
- [x] 3.3 Merge user `values` over the defaults with `default_merger` and dump `headlamp-values.yaml`; verify with `HostnameTest.test_auth_proxy_backend`
- [x] 3.4 Document "Headlamp Behind Authentication Proxy" in Installation.md; verify that the documented `values` match the `test_auth_proxy_backend` case
- [x] 3.5 Add `kubemarine.plugins.headlamp` to `kubemarine.spec` hidden imports; verify that the PyInstaller build includes the module

## 4. Summary report

- [x] 4.1 Add `SummaryItem.HEADLAMP_URL` (after Dashboard URL) and implement `get_url` / `schedule_summary_report` with the HTTPS/HTTP selection rule; verify that the summary shows the URL after `install --tasks deploy.plugins`

## 5. Upgrade support

- [x] 5.1 Add `headlamp: []` to `patches/software_upgrade.yaml` and its etalon copy; verify with `test_migrate_kubemarine.py`
- [x] 5.2 Add `debugImage` to the sensitive keys in `plugins.verify_image_redefined`; verify with `test_enrich_headlamp` and `test_headlamp_require_image_redefinition`

## 6. PaaS checks

- [x] 6.1 Implement `kubernetes_headlamp_status` (test 237: skipped when not installed, Service probe with IPv6 support, HTTPS ingress probe with retries) and register it as `kubernetes.plugins.headlamp`; verify on a cluster with Headlamp installed that `check_paas --tasks kubernetes.plugins.headlamp` reports "available"
- [x] 6.2 Add the Headlamp namespace to test 207 and the Headlamp Deployment to the default services configuration (image `v<appVersion>`) and health checks; verify that `check_paas` passes on a cluster with Headlamp
- [x] 6.3 Change `break` to `continue` in `default_services_health_status` so that plugins which are not installed do not stop evaluation; verify that a cluster with an earlier plugin disabled still checks Headlamp
- [x] 6.4 Document test 237 and the updated service lists in `docs/public/Kubecheck.md`; verify that the TOC and task tree entries are present

## 7. Deprecation, migration docs, CI

- [x] 7.1 Mark `kubernetes-dashboard` deprecated and add "Dashboard migration to Headlamp" to Installation.md; verify that the procedure steps and rollback are present
- [x] 7.2 Add the Headlamp and alpine images to the supported-versions image tables in Installation.md; verify that the versions match the compatibility map
- [x] 7.3 Enable Headlamp with hostname `headlamp.{{ cluster_name }}` in `ci/default_cluster.yaml` and `ci/extended_cluster.yaml` (plus an `/etc/hosts` entry); verify that CI install and `check_paas` pass

## 8. Integration verification

- [x] 8.1 Run the full unit test suite (`python -m pytest test/unit`) and verify that there are no regressions
- [x] 8.2 Confirm that the CI pipelines for the default and extended clusters pass with Headlamp installed alongside kubernetes-dashboard (test 237 "available", test 208 still passes)