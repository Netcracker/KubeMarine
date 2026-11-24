# Spec Delta

## Purpose

Defines the post-installation PaaS checks (`check_paas` procedure) that verify the availability, configuration, and health of cluster components and out-of-box plugins.

## ADDED Requirements

### Requirement: Headlamp availability check
The system SHALL provide test `237 Headlamp Availability` as task `kubernetes.plugins.headlamp`. It SHALL succeed with "skipped" when Headlamp is not installed. Otherwise it SHALL check, from the first control-plane node and with retries, that the Headlamp Service returns HTTP 200 and that the Headlamp URL returns HTTP 200 through the ingress on port 443.

#### Scenario: Headlamp not installed
- **WHEN** `plugins.headlamp.install` is false
- **THEN** test 237 succeeds with result "skipped"

#### Scenario: Headlamp available
- **WHEN** the Headlamp Service and the HTTPS ingress endpoint for `hostname` both return HTTP 200
- **THEN** test 237 succeeds with result "available"

#### Scenario: Service unavailable
- **WHEN** the Headlamp Service cannot be found or does not return HTTP 200 within the retries
- **THEN** test 237 fails, with a hint to verify Headlamp in its namespace

#### Scenario: Ingress unavailable
- **WHEN** the Service is available but `https://<hostname>/`, resolved to the control-plane internal address, does not return HTTP 200 within the retries
- **THEN** test 237 fails with "ingress is not available"

#### Scenario: IPv6 service address
- **WHEN** the Headlamp Service has an IPv6 cluster IP
- **THEN** the check reaches the Service using a bracketed IPv6 address

### Requirement: Headlamp namespace in pods condition check
Test `207 Pods Condition` SHALL include the configured Headlamp namespace among the system namespaces it inspects.

#### Scenario: Failing Headlamp pod
- **WHEN** a pod in the Headlamp namespace is in a critical state
- **THEN** test 207 reports it like pods in the other system namespaces

### Requirement: Headlamp in default services configuration check
When Headlamp is installed, the default services configuration check SHALL verify that the Headlamp Deployment's image version matches the chart's `appVersion` (`v<appVersion>`) for the configured chart version.

#### Scenario: Image version mismatch
- **WHEN** the Headlamp Deployment runs an image tag that differs from the expected chart `appVersion`
- **THEN** the configuration check reports the mismatch

### Requirement: Headlamp in default services health check
When Headlamp is installed, the default services health check SHALL verify that the Headlamp Deployment in its namespace is ready.

#### Scenario: Headlamp deployment not ready
- **WHEN** Headlamp is installed and its Deployment is not ready
- **THEN** the health check reports the Headlamp Deployment as not ready

### Requirement: Health check evaluates every installed plugin
The default services health check SHALL skip only the plugins that are not installed, and SHALL still evaluate every installed out-of-box plugin regardless of its order in the plugin list.

#### Scenario: Earlier plugin not installed
- **WHEN** a plugin earlier in the out-of-box plugin order is not installed and a later plugin (for example Headlamp) is installed
- **THEN** the later plugin's workloads are still included in the health check
