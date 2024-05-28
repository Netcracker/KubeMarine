# Registration and implementation of upgrade patches

## Status

Approved

## Context

We have [migrate_kubemarine](../Maintenance.md#kubemarine-migration-procedure) procedure,
but have no stable process to deliver new versions of software (plugin, thirdparties, packages) 
that we recommend for existing Kubernetes versions.

## Decision

The implementation is split into two parts:
1. Automatic and manual registration of what software to upgrade for what Kubernetes versions.
2. Implementation of upgrade process for each type of software. 
   It should be developed once and persisted in Kubemarine sources.

### Registration

New config file `kubemarine/patches/software_upgrade.yaml` holds what software for what Kubernetes versions should be upgraded by current Kubemarine version.

The file is mostly automatically managed by third-party management tool `scripts/thirdparties/sync.py`.
It should still be possible to manually specify what packages to upgrade.

Supported software for upgrade: crictl, cri (containerd), haproxy, keepalived, all out-of-box plugins.

The file is automatically cleared after new Kubemarine release / iteration.

### Procedure

There should be separate patch for each instance of software. The order of upgrade is the following:
* crictl
* CRI
* haproxy
* keepalived
* Separate upgrade patch for each plugin according to their default priority.

If there is nothing to upgrade for the particular instance of software,
the corresponding patch should not be shown in the list and not executed.

The procedure to upgrade each type of software should be similar to that in 
Kubernetes [upgrade](../Maintenance.md#upgrade-procedure) procedure.

#### Patches priority

New concept of patches priority. Patches with higher priority are always executed after patches with lower priority.

1. **Inventory-only patches**. Can only patch initial inventory.
   Instantiation of KubernetesCluster is not allowed, and connection to nodes is not allowed.
2. **Software upgrade patches**.
3. **Other patches**. Should not affect software upgrade.
   May patch initial inventory and operate with cluster.

#### Inventory

Introduce procedure inventory for Kubemarine migration procedure.

#### crictl

If `crictl` source is redefined in the initial inventory file,
new source must be specified in the procedure inventory.
The new source is moved to the cluster inventory, and the third party is re-installed.

#### CRI

If package associations are redefined in the initial inventory file,
new associations must be specified in the procedure inventory.

Configuration from the procedure inventory is merged with the cluster inventory,
and the upgrade is started with the following steps for each node one by one:
1. drain node
2. upgrade CRI
3. remove all containers
4. the node is again allowed for scheduling.

#### Balancers

If package associations are redefined in the initial inventory file,
new associations must be specified in the procedure inventory.

Configuration from the procedure inventory is merged with the cluster inventory, and haproxy / keepalived is reinstalled.

#### Plugins

If the initial inventory file contains redefined images or version for the plugin,
new image MUST be specified in the procedure inventory.

Configuration from the procedure inventory is merged with the cluster inventory,
and the plugin is re-installed.

## Consequences

1. We have an ability to upgrade different types of software as part of Kubemarine migration.
   Maintenance of third-parties will be simplified.
2. Kubemarine migration becomes more complex from the user side, but at the same time it becomes more robust.
