# headlamp-plugin Specification

## Purpose

Provides Headlamp as an optional out-of-box Kubernetes web UI plugin for KubeMarine clusters, the successor to the deprecated kubernetes-dashboard plugin.

## Requirements

### Requirement: Headlamp plugin is optional and disabled by default
The system SHALL provide a `headlamp` plugin under `plugins.headlamp` with `install: false` by default, and SHALL deploy it only when `install` is `true`.

#### Scenario: Default inventory
- **WHEN** the inventory does not mention `plugins.headlamp`
- **THEN** Headlamp is not installed and no Headlamp resources are created

#### Scenario: Plugin enabled
- **WHEN** the inventory sets `plugins.headlamp.install: true` and the plugins are deployed
- **THEN** a Headlamp Helm release is installed and its Deployment and pods become ready

### Requirement: Headlamp inventory schema
The system SHALL accept only these plugin-specific properties, in addition to the generic plugin properties: `version`, `namespace`, `releaseName`, `hostname`, `headlampRegistry`, `debugRegistry`, `debugImage`, `values`. Unknown properties SHALL fail inventory validation.

#### Scenario: Unknown property
- **WHEN** `plugins.headlamp` contains a property not in the allowed set
- **THEN** inventory validation fails

### Requirement: Headlamp configuration defaults
When `install` is true, the system SHALL default to: namespace `headlamp`, release name `headlamp`, hostname `dashboard.{{ cluster_name }}`, and chart version and `debugImage` (`library/alpine:<version>`) taken from the compatibility map for the cluster's Kubernetes version.

#### Scenario: Defaults applied
- **WHEN** Headlamp is enabled with no other settings on a supported Kubernetes version
- **THEN** the release `headlamp` is installed in namespace `headlamp` with chart `v0.46.0` and debug image `library/alpine:3.24.2`

#### Scenario: Custom namespace and release name
- **WHEN** `namespace` and `releaseName` are set
- **THEN** the release, Deployment, Service, Ingress, and HTTPRoute use the given release name in the given namespace

### Requirement: Secure workload defaults
The system SHALL deploy Headlamp pods that satisfy the `restricted` Pod Security Standard by default: run as non-root (UID 100, GID 101), no privilege escalation, all capabilities dropped, `RuntimeDefault` seccomp. Pods SHALL be scheduled on Linux nodes and have default resource requests and limits.

#### Scenario: Restricted namespace
- **WHEN** Headlamp is installed into a namespace that enforces the `restricted` PSS profile
- **THEN** Headlamp pods are admitted and run

### Requirement: Node shell and pod debug image
The system SHALL configure Headlamp to use the resolved debug image for both node shell pods and pod debug containers, SHALL create node shell pods in `kube-system` by default, and SHALL disable bundled static plugins by default.

#### Scenario: Debug image propagation
- **WHEN** Headlamp is installed
- **THEN** the node shell image and the pod debug image are both the resolved debug image, and the node shell namespace is `kube-system`

### Requirement: User value overrides
The system SHALL deep-merge `plugins.headlamp.values` over KubeMarine's chart defaults, with user values taking precedence. Lists in user values SHALL replace the corresponding default lists, while sibling defaults are preserved.

#### Scenario: Override resources
- **WHEN** `values.resources.requests.cpu` is set to `200m`
- **THEN** the release uses a CPU request of `200m` while the other KubeMarine defaults stay in place

#### Scenario: Auth proxy backend
- **WHEN** `values.ingress.hosts` and `values.httpRoute.rules` point to an authentication proxy service
- **THEN** the Ingress and HTTPRoute route to that service, and the default TLS hosts, ingress class, HTTPRoute hostnames, and parentRefs are preserved

### Requirement: Exposure via installed ingress controllers
The system SHALL create an `Ingress` (class `nginx`, TLS with the controller's default certificate) when `nginx-ingress-controller` is installed. It SHALL create an `HTTPRoute` attached to `default-external-gateway` when `envoy-gateway` is installed. Both SHALL use `hostname`.

#### Scenario: Only nginx installed
- **WHEN** only `nginx-ingress-controller` is installed
- **THEN** an Ingress for `hostname` is created and no HTTPRoute is created

#### Scenario: Only envoy installed
- **WHEN** only `envoy-gateway` is installed
- **THEN** an HTTPRoute for `hostname` attached to `default-external-gateway` in the envoy-gateway namespace is created and no Ingress is created

#### Scenario: Both installed
- **WHEN** both ingress plugins are installed
- **THEN** both resources are created, and the Ingress is marked to be ignored by the Gateway API converter so that no duplicate route is generated

#### Scenario: No ingress controller
- **WHEN** neither ingress plugin is installed
- **THEN** neither an Ingress nor an HTTPRoute is created

### Requirement: Image registry resolution
The system SHALL resolve each image registry in this order, from highest priority to lowest: the plugin-specific key (`headlampRegistry` or `debugRegistry`), then `plugins.headlamp.installation.registry`, then `plugin_defaults.installation.registry`, then the default. The default is `ghcr.io` for the Headlamp image; for the debug image, no registry prefix is added.

#### Scenario: No registries configured
- **WHEN** no registries are set
- **THEN** the Headlamp image registry is `ghcr.io` and the debug image is `library/alpine:<version>` with no prefix

#### Scenario: plugin_defaults registry
- **WHEN** only `plugin_defaults.installation.registry` is set to `R`
- **THEN** both images use registry `R`

#### Scenario: Plugin installation registry
- **WHEN** both `plugin_defaults` and `plugins.headlamp.installation.registry` (`P`) are set
- **THEN** both images use `P`

#### Scenario: Specific registry wins
- **WHEN** `headlampRegistry` is set to `H` and `installation.registry` is set to `P`
- **THEN** the Headlamp image uses `H` and the debug image uses `P`

### Requirement: Hostname conflict validation with kubernetes-dashboard
The system SHALL fail inventory validation when both `headlamp` and `kubernetes-dashboard` are set to be installed with the same hostname. The error SHALL ask the user to set a different `hostname` for one of them.

#### Scenario: Same hostname
- **WHEN** both plugins are installed with default hostnames
- **THEN** inventory validation fails with an error naming the conflicting hostname

#### Scenario: Different hostnames
- **WHEN** both plugins are installed and `headlamp.hostname` is `headlamp.{{ cluster_name }}`
- **THEN** validation passes and Headlamp is exposed on `headlamp.<cluster_name>`

#### Scenario: Dashboard not installed
- **WHEN** `kubernetes-dashboard.install` is false and the hostnames are equal
- **THEN** validation passes

### Requirement: Headlamp URL in summary report
After a successful Headlamp installation, the system SHALL add a "Headlamp URL" entry to the summary report when an Ingress or HTTPRoute is created. The scheme SHALL be `https` if nginx is installed or envoy-gateway has a certificate and key configured; otherwise it SHALL be `http`.

#### Scenario: Envoy without certificate
- **WHEN** only envoy-gateway is installed and its external gateway certificate is empty
- **THEN** the summary shows `http://<hostname>`

#### Scenario: Nginx installed
- **WHEN** nginx-ingress-controller is installed
- **THEN** the summary shows `https://<hostname>`

#### Scenario: No exposure
- **WHEN** no ingress plugin is installed
- **THEN** no Headlamp URL entry is reported

### Requirement: Kubernetes version compatibility and upgrade
The system SHALL define a Headlamp chart version and alpine version for every supported Kubernetes version. It SHALL support Headlamp upgrade patches, treating `debugImage` as an image key: if the user redefines `debugImage` in the inventory, the upgrade procedure inventory MUST redefine it too.

#### Scenario: Upgrade with redefined debugImage
- **WHEN** a Headlamp upgrade patch runs, `debugImage` is redefined in the cluster inventory, and it is not redefined in the upgrade procedure inventory
- **THEN** the procedure fails with error KME0009 for key `debugImage` and plugin `headlamp`

#### Scenario: Upgrade enriches debugImage
- **WHEN** the upgrade procedure inventory sets `upgrade.plugins.headlamp.debugImage`
- **THEN** the upgraded inventory uses that `debugImage`
