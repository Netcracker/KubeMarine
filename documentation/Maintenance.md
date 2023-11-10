This section describes the features and steps for performing maintenance procedures on the existing Kubernetes cluster.

- [Prerequisites](#prerequisites)
- [Provided Procedures](#provided-procedures)
    - [Kubemarine Migration Procedure](#kubemarine-migration-procedure)
      - [Software Upgrade Patches](#software-upgrade-patches)
    - [Upgrade Procedure](#upgrade-procedure)
    - [Backup Procedure](#backup-procedure)
    - [Restore Procedure](#restore-procedure)
    - [Add Node Procedure](#add-node-procedure)
      - [Operating System Migration](#operating-system-migration)
    - [Remove Node Procedure](#remove-node-procedure)
    - [Manage PSP Procedure](#manage-psp-procedure)
    - [Manage PSS Procedure](#manage-pss-procedure)
    - [Reboot Procedure](#reboot-procedure)
    - [Certificate Renew Procedure](#certificate-renew-procedure)
    - [Cri Migration Procedure](#cri-migration-procedure)
    - [Admission Migration Procedure](#admission-migration-procedure)
- [Procedure Execution](#procedure-execution)
    - [Procedure Execution From CLI](#procedure-execution-from-cli)
    - [Logging](#logging)
    - [Inventory Preservation](#inventory-preservation)
    - [Additional Parameters](#additional-parameters)
      - [Grace Period and Drain Timeout](#grace-period-and-drain-timeout)
      - [Images Prepull](#images-prepull)
- [Additional Procedures](#additional-procedures)
    - [Changing Calico Settings](#changing-calico-settings)
    - [Data Encryption in Kubernetes](#data-encryption-in-kubernetes)
    - [Changing Cluster CIDR](#changing-cluster-cidr)
    - [Kubelet Server Certificate Approval](#kubelet-server-certificate-approval)
- [Common Practice](#common-practice)

# Prerequisites

Before you start any maintenance procedure, you must complete the following mandatory steps:

1. Verify the environment for compliance with the prerequisites described in the [Kubemarine Installation Prerequisites](Installation.md#prerequisites) section in _Kubemarine Installation Procedure_.
1. Ensure that all the nodes are up, online, and healthy (except dead nodes, when you trying to remove them). This applies to the new nodes as well as the existing nodes.
1. If using custom registries, make sure they are online, accessible from nodes, and you are able to download images from the registries.
1. If using custom RPM repositories, make sure they are online, accessible from nodes, and you are able to perform repository updates.
1. Prepare the latest actual **cluster.yaml** that should contain information about the current cluster state. For more information, refer to the [Kubemarine Inventory Preparation](Installation.md#inventory-preparation) section in _Kubemarine Installation Procedure_.

   **Note**: If you provide an incorrect config file, it can cause unknown consequences.

1. Prepare **procedure.yaml** file containing the configuration for the procedure that you are about to perform. Each procedure has its own configuration format. Read documentation below to fill procedure inventory data.


# Provided Procedures

The information about the procedures for nodes is described in the following sections.

## Kubemarine Migration Procedure

The Kubemarine migration procedure allows you to automatically adopt your current Kubernetes cluster and **cluster.yaml** to a newer version of Kubemarine.
This procedure should always be considered when taking new versions of Kubemarine if it is going to be used on the existing clusters that are managed by the previous versions of Kubemarine.

Remember the following when upgrading Kubemarine:
* Inspect all Kubemarine intermediate tags if they require some additional steps for migration.
* Decide whether these steps should be applied.
* If the steps should be done manually, perform them.
  If they can be automated, checkout the necessary Kubemarine tag and apply the necessary *patches*.
  For more information, refer to the [Patch Identifiers](#patch-identifiers) section.

**Note**: As much as any other maintenance procedure, `migrate_kubemarine` can make the cluster temporarily unavailable.
**Note**: Rollback is not supported. To revert to previous Kubemarine version need to reinstall it.

#### Patch Identifiers

To know if the given Kubemarine tag provides any automatic patch, it is necessary to inspect its release notes.
Alternatively, it is possible to checkout this tag and call `migrate_kubemarine --list`.
The output contains zero or more *patch identifiers*, each listed on a new line.

To receive more information about the chosen patch, it is necessary to call `migrate_kubemarine --describe <patch identifier>`.

#### Migration Process

If called without arguments, `migrate_kubemarine` tries to apply all patches in the current tag.
Kubemarine applies the patches in a strict order, though it is possible to choose only a subset of patches or skip not necessary patches.
Use `migrate_kubemarine --force-apply <patches>` or `migrate_kubemarine --force-skip <patches>` correspondingly,
where, `<patches>` are the patch identifiers separated by comma.

### Kubemarine Migration Procedure Parameters

The procedure accepts optional positional argument with the path to the procedure inventory file.
You can find description and examples of the accepted parameters in the next sections.

The JSON schema for procedure inventory is available by [URL](../kubemarine/resources/schemas/migrate_kubemarine.json?raw=1).
For more information, see [Validation by JSON Schemas](Installation.md#inventory-validation).

### Software Upgrade Patches

The new Kubemarine version may have new recommended versions of different types of software in comparison to the old version.
To make the new Kubemarine and installed cluster consistent to each other, it is necessary to upgrade the corresponding software.

For each software, it is possible to supply additional parameters in the procedure configuration.
After each upgrade, the `cluster.yaml` is regenerated to reflect the actual cluster state.
Use the latest updated `cluster.yaml` configuration to further work with the cluster.

**Note**: The upgrade procedure is as much fine-grained as possible.
The cluster is unaffected if the upgrade is not relevant for the currently used Kubernetes version, OS family, container runtime, and so on.

#### Upgrade CRI Patch

The container runtime is upgraded by the `upgrade_cri` patch.
For more information, refer to [Packages Upgrade Patches](#packages-upgrade-patches).

The upgrade is performed node-by-node. The process for each node is as follows:
1. All the pods are drained from the node.
2. The docker or containerd is upgraded.
3. All containers on the node are deleted.
4. The node is returned to the cluster for scheduling.

By default, node drain is performed using `disable-eviction=True` to ignore the PodDisruptionBudget (PDB) rules.
For more information, refer to the [Kubernetes Upgrade Task](#kubernetes-upgrade-task) section of the Kubernetes upgrade procedure.

The upgrade procedure is always risky, so you should plan a maintenance window for this procedure.
You may encounter issues that are similar to that of the [Kubernetes Upgrade Task](#kubernetes-upgrade-task) of the Kubernetes upgrade procedure.
In such a case, refer to the corresponding section in the [Troubleshooting Guide](Troubleshooting.md#failures-during-kubernetes-upgrade-procedure).

**Note**: All containers on the node are deleted after the upgrade.
Kubernetes re-creates all the pod containers.
However, your custom containers may be deleted, and you need to start them manually.

**Note**: [Grace Period and Drain Timeout](#grace-period-and-drain-timeout) additional parameters are also applicable.

#### Thirdparties Upgrade Patches

Patches that upgrade thirdparties have the following identifiers:
* `upgrade_crictl` - It upgrades the `/usr/bin/crictl` third-party, if necessary.
* `upgrade_calico` - It upgrades the `/usr/bin/calicoctl` third-party as part of the Calico plugin upgrade.

If the cluster is located in an isolated environment,
it is possible to specify the custom paths to new thirdparties with a similar syntax as in the `cluster.yaml`
as shown in the following snippet:
```yaml
upgrade:
  thirdparties:
    /usr/bin/calicoctl:
      source: https://example.com/thirdparty.files/projectcalico/calico/v3.25.1/calicoctl-linux-amd64
    /usr/bin/crictl.tar.gz:
      source: https://example.com/thirdparty.files/kubernetes-sigs/cri-tools/v1.27.0/crictl-v1.27.0-linux-amd64.tar.gz
```

This configuration replaces the configuration contained in the current `cluster.yaml`.

By default, it is not required to provide information about thirdparties.
They are upgraded automatically as required.
You can provide this information if you want to have better control over their versions.
Also, you have to explicitly provide thirdparties `source` if you have specified this information in the `cluster.yaml`.
It is because in this case, you take full control over the thirdparties' versions and the defaults do not apply.

#### Packages Upgrade Patches

Patches that upgrade system packages have the following identifiers:
* `upgrade_cri` - It upgrades packages participating in the container runtime.
   For more information, refer to [Upgrade CRI Patch](#upgrade-cri-patch).
* `upgrade_haproxy` - It upgrades the Haproxy service on all balancers.
* `upgrade_keepalived` - It upgrades the Keepalived service on all balancers.

System packages such as docker, containerd, haproxy, and keepalived are upgraded automatically as required.
You can influence the system packages' upgrade using the `packages` section as follows:

```yaml
upgrade:
  packages:
    associations:
      docker:
        package_name:
          - docker-ce-cli-19.03*
          - docker-ce-19.03*
```

The configuration from the procedure inventory is merged with the configuration in the `cluster.yaml`.

By default, it is not required to provide information about system packages through associations.
You can provide this information if you want to have better control over system packages' versions.
Also, you have to explicitly provide system packages' information if you have specified this information in the `cluster.yaml`.
It is because in this case, you take full control over the system packages and the defaults do not apply.

**Note**: Upgrade of Haproxy and Keepalived makes the cluster temporarily unavailable.

#### Plugins Upgrade Patches

Patches that upgrade the OOB plugins have the following identifiers:
* `upgrade_calico` - It upgrades the Calico plugin.
* `upgrade_nginx_ingress_controller` - It upgrades the NGINX Ingress Controller plugin.
* `upgrade_kubernetes_dashboard` - It upgrades the Kubernetes dashboard plugin.
* `upgrade_local_path_provisioner` - It upgrades the Local Path Provisioner plugin.

The plugins are upgraded automatically,
but you can influence their upgrade using the `plugins` section as follows:

```yaml
upgrade:
  plugins:
    calico:
      node:
        image: 'calico/node:v3.25.1'
```

After applying, this configuration is merged with the plugins' configuration contained in the current `cluster.yaml`.

**Note**: If you have changed images for any of the plugins in the `cluster.yaml`,
it is required to explicitly specify new images in the procedure inventory for those plugins.
The configuration format for the plugins is the same.

## Upgrade Procedure

**Warnings**: 
* Follow Kubernetes upgrade best practises, like:
  * Have a number of replicas configured for Application Microservices
  * [Pod anti-affinity](https://kubernetes.io/docs/concepts/scheduling-eviction/assign-pod-node/#inter-pod-affinity-and-anti-affinity) rules should be configured to avoid placement of more than one pod replicas on the  same worker node
  * [PodDisruptionBudget](https://kubernetes.io/docs/tasks/run-application/configure-pdb) is configured for desired Deployments
  * https://kubernetes.io/docs/tasks/run-application/configure-pdb/#unhealthy-pod-eviction-policy is configured to _AlwaysAllow_
* API versions `extensions/v1beta1` and `networking.k8s.io/v1beta1` are not supported starting from Kubernetes 1.22 and higher. Need to update ingress to the new API `networking.k8s.io/v1`. More info: https://kubernetes.io/docs/reference/using-api/deprecation-guide/#ingress-v122
* Before starting the upgrade, make sure you make a backup. For more information, see the section [Backup Procedure](#backup-procedure).
* The upgrade procedure only maintains upgrading from one `supported` version to the next `supported` version. For example, from 1.18 to 1.20 or from 1.20 to 1.21.
* Since Kubernetes v1.25 doesn't support PSP, any clusters with `PSP` enabled must be migrated to `PSS` **before the upgrade** procedure running. For more information see the [Admission Migration Procedure](#admission-migration-procedure). The migration procedure is very important for Kubernetes cluster. If the solution doesn't have appropriate description about what `PSS` profile should be used for every namespace, it is better not to migrate from PSP for a while.  

### Upgrade Procedure Parameters

The procedure accepts required positional argument with the path to the procedure inventory file.
You can find description and examples of the accepted parameters in the next sections.

The JSON schema for procedure inventory is available by [URL](../kubemarine/resources/schemas/upgrade.json?raw=1).
For more information, see [Validation by JSON Schemas](Installation.md#inventory-validation).

#### Upgrade Plan

The upgrade procedure allows you to automatically update Kubernetes cluster and its core components to a new version. To do this, you must specify the `upgrade_plan` in the procedure config, and fill in the new version of the Kubernetes cluster you want to upgrade to. For example:

```yaml
upgrade_plan:
  - v1.18.8
  - v1.19.3
```

**Note**: Be sure to check the version string format and do not forget to specify the letter `v` at the beginning of the string.

**Note**: It is not possible to skip minor Kubernetes versions. For example, to upgrade from 1.18.8 to 1.20.2, you have to first upgrade to the intermediate 1.19.3 version.

After starting the upgrade procedure, the script validates the correctness of the entered upgrade plan. If it contains issues, the update does not start, and a message with the problem description is displayed. If there are no errors, the following log with loaded update plan is displayed:

```
Loaded upgrade plan: current ⭢ v1.16.12
Loading inventory file 'cluster.yaml'


------------------------------------------
UPGRADING KUBERNETES v1.18.8 ⭢ v1.19.3
------------------------------------------
```

The script upgrades Kubernetes versions one-by-one. After each upgrade, the `cluster.yaml` is regenerated to reflect the actual cluster state. Use the latest updated `cluster.yaml` configuration to further work with the cluster.

#### Upgrading Specific Nodes

**Note**: Kubemarine automatically determines already upgraded nodes and excludes them from the Kubernetes upgrade procedure. Use manual nodes specifying for updating in exceptional cases when the problem cannot be solved automatically. Also, if any of the nodes are not available, first remove the node from the cluster, instead of changing the list of nodes for the upgrade.

**Warning**: By manually specifying the nodes for the upgrade, you completely take control of yourself and bear all the consequences of an unsuccessful upgrade. 

In special cases, a situation may arise when you need to manually specify certain nodes that need to be upgraded. For such situations, a parameter, `upgrade_nodes`, is available in the procedure configuration. Within this parameter, list all the nodes that you want to upgrade. Specify the nodes in the same format in which they are specified in your main `cluster.yaml` config. 

For Example:

```yaml
upgrade_nodes:
  - name: worker-10
    address: 10.101.10.10
    internal_address: 192.168.101.10
    roles: [worker]
  - name: worker-11
    address: 10.101.10.11
    internal_address: 192.168.101.11
    roles: [worker]
```

A shortened format is also supported.

```yaml
upgrade_nodes:
  - worker-10
  - worker-11
```

Based on the example above, only the nodes `worker-10` and `worker-11` are updated, the rest are skipped.

**Note**: The nodes are excluded only from the Kubernetes upgrade. All other upgrade tasks like thirdparties, coredns, and so on are performed for all the nodes as they are. 

#### Nodes Saved Versions Before Upgrade

During the upgrade, a temporary file `/etc/kubernetes/nodes-k8s-versions.txt` is created on first control-plane node that saves the state and versions of the nodes prior to the initial upgrade.
If the procedure fails and certain nodes for the upgrade are not manually specified, the saved versions of the nodes before the upgrade are used to determine the initial state of the nodes.
In case of a successful upgrade of a node, the information about it is deleted from the state file so as to not upgrade it again.
If the entire update cycle completes successfully, this temporary file is deleted, and in further upgrades it is generated anew.
At the same time, there may be situations when this file interferes with a normal upgrade - in this case, you can erase it or use manually specified nodes for the upgrade.

#### Custom Settings Preservation for System Service

If the system service (`etcd`, `kube-apiserver`,`kube-controller`, `kube-scheduler`) configuration changes during the operation process, the changes should be reflected in the `kubeadm-config` configmap. Following is an example for `etcd`. Pay attention to the fact that the manifest file and configmap structure are different.

`/etc/kubernetes/manifests/etcd.yaml`:
```yaml
...
spec:
  containers:
  - command:
    - etcd
    - --heartbeat-interval=1000
    - --election-timeout=10000
...
```
`kubeadm-config` configmap:
```yaml
...
etcd:
  local:
    extraArgs:
      heartbeat-interval: "1000"
      election-timeout: "10000"
...
```

**Note**: All the custom settings for the system services should be properly reflected in the cluster.yaml (see [services.kubeadm parameters](Installation.md#kubeadm)) to be kept after upgrade.


#### Thirdparties Upgrade Section and Task

If the cluster is located in an isolated environment, it is possible to specify the custom paths to new thirdparties with the same syntax as in the `cluster.yaml` as shown in the following script:

```yaml
v1.24.2:
  thirdparties:
      /usr/bin/kubeadm:
        source: https://example.com/thirdparty.files/kubernetes/kubeadm/v1.24.2/bin/linux/amd64/kubeadm
      /usr/bin/kubelet:
        source: https://example.com/thirdparty.files/kubernetes/kubelet/v1.24.2/bin/linux/amd64/kubelet
      /usr/bin/kubectl:
        source: https://example.com/thirdparty.files/kubernetes/kubectl/v1.24.2/bin/linux/amd64/kubectl
      /usr/bin/calicoctl:
        source: https://example.com/thirdparty.files/projectcalico/calico/v3.22.2/calicoctl-linux-amd64
```

This configuration replaces the configuration contained in the current `cluster.yaml`.

#### Kubernetes Upgrade Task

This task is required to actually upgrade the Kubernetes cluster to the next version. The upgrade is performed node-by-node. On each node, the docker or containerd is upgraded, if required. After all the pods are drained from the node, the node is upgraded and finally returned to the cluster for scheduling.

By default, node drain is performed using `disable-eviction=True` to ignore the PodDisruptionBudget (PDB) rules. If you want to enforce PDB rules during the upgrade, set `disable-eviction` to False. However, in this case, the upgrade may fail if you are unable to drain the node due of PDB rules. `disable-eviction` works only for upgrades on Kubernetes versions >= 1.18. 
An example configuration to enforce PDB rules is as follows:

```yaml
upgrade_plan:
  - v1.18.8

disable-eviction: False # default is True
```

The upgrade procedure is always risky, so you should plan a maintenance window for this procedure. If you encounter issues during the Kubernetes cluster upgrade, refer to the [Troubleshooting guide](Troubleshooting.md#failures-during-kubernetes-upgrade-procedure).

**Note**: During the upgrade, some or all internal Kubernetes certificates are updated. Do not rely on upgrade procedure to renew all certificates. Check the certificates' expiration using the `cert_renew` procedure for every 3 months independently of the upgrades
and plan the certificates' renewal accordingly.

#### CoreDNS Upgrade Task

This task is executed to restore the required CoreDNS configuration.

**Warning**: To prevent the loss of the modified CoreDNS configuration (in case the configuration was modified by the cloud administrator and etc) - you must specify this CoreDNS configuration in the `cluster.yaml`, otherwise the configuration will be lost.

#### Packages Upgrade Section and Task

This inventory section contains the configuration to upgrade custom and system packages, such as docker and containerd. The system packages are upgraded by default, if necessary. You can influence the system packages' upgrade and specify custom packages for the upgrade/installation/removal using the `packages` section as follows:

```yaml
v1.18.8:
  packages:
    remove:
      - curl
    install:
      - unzip
      - policycoreutils-python
    upgrade:
      - openssl
    associations:
      docker:
        package_name:
          - docker-ce-cli-19.03*
          - docker-ce-19.03*
```

The requested actions for custom packages are performed in the `packages` task. The configuration from the procedure inventory replaces the configuration specified in the `cluster.yaml`. If you do not want to lose the packages specified in the `cluster.yaml`, then it is necessary to copy them to the procedure inventory.

By default, it is not required to provide information about system packages through associations. They are upgraded automatically as required. You can provide this information if you want to have better control over system packages' versions, such as docker. Also, you have to explicitly provide system packages' information if you have specified this information in the `cluster.yaml`. It is because in this case, you take full control over the system packages and the defaults do not apply. The provided configuration for system packages is merged with configuration in the `cluster.yaml`.

**Note**: The system packages are updated in separate tasks. For example, the container runtime (docker/containerd) is upgraded during the Kubernetes upgrade.

**Note**: During the container runtime upgrade, the containers may be broken, so all containers on the node are deleted after the upgrade.
Kubernetes re-creates all the pod containers. However, your custom containers may be deleted, and you need to start them manually.

#### Plugins Upgrade Section and Task

This task is required to upgrade OOB plugins and specified user plugins. The OOB plugins are upgraded automatically. You can also configure your own plugins for the upgrade as follows:

```yaml
v1.18.10:
  plugins:
    example-plugin:
      installation:
        procedures:
          - template:
              source: /var/data/template.yaml.j2
              destination: /etc/example/configuration.yaml
              apply_required: true
              sudo: true
              destination_groups: ['control-plane']
              destination_nodes: ['worker-1']
              apply_groups: None
              apply_nodes: ['control-plane-1', 'worker-1']
              apply_command: 'testctl apply -f /etc/example/configuration.yaml'
```

After applying, this configuration is merged with the plugins' configuration contained in the current `cluster.yaml`. Only the `installation` section for each plugin is overwritten, if specified.

**Note**: The plugins should be idempotent and it should be possible to install them several times. Also, note that plugins are installed over previously installed plugins, so they should perform the necessary clean-ups.

**Note**: If you have changed images for any of the OOB plugins in the `cluster.yaml`, it is required to explicitly specify new images in the procedure inventory for that particular plugin. The configuration format for OOB plugins is the same.

### Upgrade Procedure Tasks Tree

The `upgrade` procedure executes the following sequence of tasks:

* verify_upgrade_versions
* thirdparties
* prepull_images
* kubernetes
* kubernetes_cleanup
* packages
* plugins
* overview

## Backup Procedure

**Note**: Before starting the backup, make sure all nodes are online and accessible.

The backup procedure automatically saves the following entities:
* ETCD snapshot
* Files and configs from cluster nodes
* Kubernetes resources

As a result of the procedure, you receive an archive with all the stored objects inside. The archive has approximately the following structure inside:

```text
backup-Jan-01-21-09-00-00.tar.gz
├── descriptor.yaml
├── cluster.yaml
├── ansible-inventory.ini
├── etcd.db
├── kubernetes_resources
│   ├── apiservices.apiregistration.k8s.io.yaml
│   ├── blockaffinities.crd.projectcalico.org.yaml
│   ├── ...
│   ├── podsecuritypolicies.policy.yaml
│   └── priorityclasses.scheduling.k8s.io.yaml
│   ├── default
│   │   ├── endpoints.yaml
│   │   ├── endpointslices.discovery.k8s.io.yaml
│   │   ...
│   │   ├── serviceaccounts.yaml
│   │   └── services.yaml
│   ├── ingress-nginx
│   │   ├── configmaps.yaml
│   │   ├── controllerrevisions.apps.yaml
│   │   ...
│   │   ├── secrets.yaml
│   │   └── serviceaccounts.yaml
│   ├── kube-node-lease
│   │   ├── leases.coordination.k8s.io.yaml
│   │   ├── secrets.yaml
│   │   └── serviceaccounts.yaml
│   ├── kube-public
│   │   ├── configmaps.yaml
│   │   ├── rolebindings.rbac.k8s.io.yaml
│   │   ...
│   │   ├── secrets.yaml
│   │   └── serviceaccounts.yaml
│   ├── kube-system
│   │   ├── configmaps.yaml
│   │   ├── controllerrevisions.apps.yaml
│   │   ...
│   │   ├── serviceaccounts.yaml
│   │   └── services.yaml
│   └── kubernetes-dashboard
│       ├── configmaps.yaml
│       ├── deployments.apps.yaml
│       ...
│       ├── serviceaccounts.yaml
│       └── services.yaml
└── nodes_data
    ├── balancer-1.tar.gz
    ├── control-plane-1.tar.gz
    ├── control-plane-2.tar.gz
    └── control-plane-3.tar.gz
```

### Backup Procedure Parameters

The procedure accepts optional positional argument with the path to the procedure inventory file.
You can find description and examples of the accepted parameters in the next sections.

The JSON schema for procedure inventory is available by [URL](../kubemarine/resources/schemas/backup.json?raw=1).
For more information, see [Validation by JSON Schemas](Installation.md#inventory-validation).

**Note**: There are some examples located in [procedure.yaml examples](../examples/procedure.yaml).

By default, no parameters are required. However, if necessary, you can specify custom.

#### backup_location Parameter

By default, the backup is placed into the workdirectory. However, if you want to specify a different location, you can specify it through `backup_location` parameter.
You can specify two types of path in it:
* The full path of the file, including the name. In this case, the file is saved to the specified path with the name you specified.
* Full path to the directory, without file name. In this case, the file is saved to the directory you specified, with the default name that contains the timestamp of the backup. For example:

```
  /home/centos/backup-{cluster_name}-20201214-162731.tar.gz
```

#### etcd Parameters

You can specify custom parameters for ETCD snapshot creation task. The following options are available:

* `source_node` - the name of the node to create snapshot from. The node must be a control-plane and have a ETCD data located on it.

Parameters example:

```yaml
backup_plan:
  etcd:
    source_node: control-plane-1
```

#### nodes Parameter

By default, the following files are backed up from all nodes in the cluster:

* /etc/resolv.conf
* /etc/hosts
* /etc/chrony.conf
* /etc/selinux/config
* /etc/systemd/system/kubelet.service
* /etc/docker/daemon.json
* /etc/containerd/config.toml
* /etc/crictl.yaml  
* /etc/haproxy/haproxy.cfg
* /etc/systemd/system/{haproxy_service_name}.service.d/{haproxy_service_name}.conf
* /etc/keepalived/keepalived.conf
* /etc/systemd/system/{keepalived_service_name}.service.d/{keepalived_service_name}.conf
* /usr/local/bin/check_haproxy.sh
* /etc/yum.repos.d/
* /etc/apt/sources.list.d/
* /etc/modules-load.d/
* /etc/audit/rules.d/
* /etc/kubernetes/
* /var/lib/kubelet/pki/

**Note**: If the file does not exist on the node, it is skipped without error.

**Note**: It is possible to backup not only files, but also directories.

If you need to add additional files for backup, or disable the default ones, you can specify this in the parameter `node` via key-value, where the key is the full file or directory path, and the value is the enable or exclude indicator. For example:

```yaml
backup_plan:
  nodes:
    /etc/resolv.conf: True
    /root: True
    /etc/hosts: False
```

#### kubernetes Parameter

The procedure exports all available Kubernetes resources from the cluster to yaml files. There are two types of resources - namespaced and non-namespaced. If you need to restrict resources for export, you can specify which ones you need.

**Note**: If the specified resource is missing, it is skipped without an error.

For the namespaced resources, you can specify the namespaces from which to export, as well as the full names of the resources to be exported. For example:
```yaml
backup_plan:
  kubernetes:
    namespaced_resources:
      namespaces:
        - default
        - kube-system
      resources:
        - secrets
        - services
        - serviceaccounts
```

Moreover, if you need to export everything, you can specify the special word `all`, as is follows:
```yaml
backup_plan:
  kubernetes:
    namespaced_resources:
      namespaces: all
      resources: all
```

For the non-namespaced resources, you can specify only full names of the resources to be exported. For example:

```yaml
backup_plan:
  kubernetes:
    nonnamespaced_resources:
      - secrets
      - services
      - serviceaccounts
```

Another example:
```yaml
backup_plan:
  kubernetes:
    nonnamespaced_resources: all
```

### Backup Procedure Tasks Tree

The `backup` procedure executes the following sequence of tasks:

* verify_backup_location
* export
  * inventory
    * cluster_yaml
    * ansible_inventory
  * lists
    * rpms
    * hostname
  * nodes
  * etcd
  * cluster_version
  * kubernetes
* make_descriptor
* pack


## Restore Procedure

**Note**: Before starting the restore, make sure that all nodes are online and accessible.

**Note**: the topology of the cluster being restored must be the same as the topology of the cluster from which the backup was created. Everything should be the same, down to the names and addresses of the nodes, their amounts and roles. If they differ, then it is recommended to perform manual recovery using the backed up Kubernetes resources from your backup archive.

**Note**: It is not necessary to define cluster.yaml for the restore procedure. In case of a missing or empty cluster, the yaml is retrieved from the backup archive.

The restore procedure automatically restores the following parts of the cluster:

* Thirdparties
* Nodes files and configs
* ETCD database

After recovery, the procedure reboots all cluster nodes.

### Restore Procedure Parameters

The procedure accepts required positional argument with the path to the procedure inventory file.
You can find description and examples of the accepted parameters in the next sections.

The JSON schema for procedure inventory is available by [URL](../kubemarine/resources/schemas/restore.json?raw=1).
For more information, see [Validation by JSON Schemas](Installation.md#inventory-validation).

**Note**: There are some examples located in [procedure.yaml examples](../examples/procedure.yaml).

To start the procedure, you must mandatory specify `backup_location` parameter. Other parameters are optional, if necessary, you can also specify them.


#### backup_location Parameter

You need to specify the required path to the file with the backup - the recovery is performed from it.

Example:

```
backup_location: /home/centos/backup-{cluster_name}-20201214-162731.tar.gz
```

#### etcd Parameters

By default, ETCD restore does not require additional parameters, however, if required, the following are supported:

* image - the full name of the ETCD image, including the registry address. On its basis, the restoration is performed.
* certificates - ETCD certificates for `etcdctl` connection to ETCD API. You can specify some certificates, or specify them all. Certificates should be presented on all nodes.

#### thirdparties Parameter

The procedure recovers thirdparties based on the `cluster.yaml`. If rpm thirdparties outdated or incorrect, specify the correct ones in this section, in the same format. For example:

```yaml
restore_plan:
  thirdparties:
    /usr/bin/kubeadm:
      source: https://storage.googleapis.com/kubernetes-release/release/v1.18.8/bin/linux/amd64/kubeadm
    /usr/bin/kubelet:
      source: https://storage.googleapis.com/kubernetes-release/release/v1.18.8/bin/linux/amd64/kubelet
    /usr/bin/kubectl:
      source: https://storage.googleapis.com/kubernetes-release/release/v1.18.8/bin/linux/amd64/kubectl
    /usr/bin/calicoctl:
      source: https://github.com/projectcalico/calicoctl/releases/download/v3.14.1/calicoctl-linux-amd64
```

**Note**: The version must match the version of Kubernetes indicated in the `cluster.yaml`.


### Restore Procedure Tasks Tree

The `restore` procedure executes the following sequence of tasks:

* prepare
  * stop_cluster
* restore
  * dns
    * resolv_conf
  * thirdparties
* import
  * nodes
  * etcd
* reboot


## Add Node Procedure

The `add_node` procedure allows you to add new nodes to an existing Kubernetes cluster. It is possible to add several nodes at a time.
Each node can have different combination of roles.

The procedure works as shown in the following table:

|Case|Expected Result|Important Note|
|---|---|---|
|Add load balancer|A new load balancer is configured. If `vrrp_ip` is present, then all the Keepalived nodes are reconfigured and restarted.|Kubernetes installation should not start. Keepalived installation should start only if `vrrp_ip` is present.|
|Add load balancer + Keepalived|A new load balancer is configured. Keepalived is installed and configured on all the load balancers.|Kubernetes installation should not start.|
|Add control-plane|Kubernetes is installed only on a new node. A new control-plane is added to the Kubernetes cluster, and all Haproxy nodes are reconfigured and restarted.|Haproxy and Keepalived installation should not start.|
|Add worker|Kubernetes is installed only on a new node. A new worker is added to the Kubernetes cluster, and all Haproxy nodes are reconfigured and restarted.|Haproxy and Keepalived installation should not start.|

Also pay attention to the following:

* Thirdparties, if any, should be installed only on new nodes. They should not be installed or updated on other nodes.
* Packages should be installed only on new nodes, and can be upgraded if the upgrade is available. Nodes that are already present in the cluster should not install or update the packages. Before running the procedure, refer to the details about the `cache_versions` option under `associations` section in the installation procedure. 
* Configs should be generated and applied only to new nodes. The only exceptions are balancers and Keepalived.
* Plugins are not reinstalled.
* System configurations like `selinux`, `modprobe`, `sysctl`, and others should be verified and configured only on new nodes.
* Only new nodes can be rebooted.
* The file `/etc/hosts` is updated and uploaded to all nodes in the cluster.

**Note**: It is not possible to change a node's role by adding an existing node again with a new role. You have to remove the node and add it again.

**Warning**: To prevent the loss of the modified CoreDNS configuration (in case the configuration was modified by the cloud administrator and etc) - you must specify this CoreDNS configuration in the `cluster.yaml`, otherwise the configuration will be lost.

### Configuring Add Node Procedure

The procedure accepts required positional argument with the path to the procedure inventory file.

The JSON schema for procedure inventory is available by [URL](../kubemarine/resources/schemas/add_node.json?raw=1).
For more information, see [Validation by JSON Schemas](Installation.md#inventory-validation).

The `nodes` configuration format for specifying new nodes is the same as that of the installation procedure. For more information, refer to [Kubemarine Inventory Nodes](Installation.md#nodes) section in _Kubemarine Installation Procedure_.

The following example demonstrates the configuration of two nodes for adding:

```yaml
nodes:
  - name: "lb"
    internal_address: "192.168.0.1"
    roles: ["balancer"]
  - name: "control-plane"
    internal_address: "192.168.0.2"
    roles: ["control-plane"]
```

**Note**:

* The connection information for new nodes can be used from defaults as described in the [Kubemarine Inventory Node Defaults](Installation.md#nodedefaults) section in _Kubemarine Installation Procedure_. If the connection information is not present by default, define the information in each new node configuration.
* If you intend to add the new `balancer` node with VRRP IP, and have previously not configured the `vrrp_ips` section, you need to do the following preliminarily:
  * And the section to the main `cluster.yaml`.
  * If you already have balancers without VRRP IPs, reconfigure the balancers and DNS,
    for example, using `kubemarine install --tasks prepare.dns.etc_hosts,deploy.loadbalancer.haproxy.configure,deploy.loadbalancer.keepalived,deploy.coredns`

### Add Node Tasks Tree

The `add_node` procedure executes the following sequence of tasks:

* cache_packages
* prepare
  * check
    * sudoer
    * system
    * cluster_installation
  * dns
    * hostname
    * resolv_conf
    * etc_hosts
  * package_manager
    * configure
    * manage_packages
  * ntp
    * chrony
    * timesyncd
  * system
    * setup_selinux
    * setup_apparmor
    * disable_firewalld
    * disable_swap
    * modprobe
    * sysctl
    * audit
      * install
      * configure
  * **cri**
    * **install** 
    * **configure**
  * thirdparties
* deploy
  * loadbalancer
    * haproxy
      * install
      * configure
    * keepalived
      * install
      * configure
  * kubernetes
    * reset
    * install
    * prepull_images
    * init (as join)
    * audit
  * admission
  * coredns
  * plugins
* overview

## Remove Node Procedure

The `remove_node` procedure removes nodes from the existing Kubernetes cluster. It is possible to remove several nodes with different combination of roles at a time. 

The procedure works as follows:

|Case|Expected Result|Important Note|
|---|---|---|
|Remove load balancer|Haproxy and Keepalived are disabled on removed nodes. Keepalived is reconfigured on all balancers.|Keepalived installation should not start.|
|Remove control-plane|Kubernetes node is deleted from the cluster and Haproxy is reconfigured on all balancers.|Haproxy and Keepalived installation should not start. Keepalived should not be reconfigured.|
|Remove worker|Kubernetes node is deleted from the cluster and Haproxy is reconfigured on all balancers.|Haproxy and Keepalived installation should not start. Keepalived should not be reconfigured.|

Also pay attention to the following:

* The `vrrp_ips` section is not touched.
  If it specifies some hosts to enable the Keepalived on, and some of these hosts no longer exist,
  such hosts are ignored with warnings.
* The file `/etc/hosts` is updated and uploaded to all remaining nodes in the cluster. The control plane address may change.
* This procedure only removes nodes and does not restore nodes to their original state. Packages, configurations, and Thirdparties are also not deleted.

Removing a node from a Kubernetes cluster is done in the following order:

1. Pods are gracefully evacuated.
1. The ETCD member is stopped and removed from the ETCD cluster.
1. Kubelet is stopped.
1. ETCD and Kubernetes data is deleted.
1. Containers are stopped and deleted. Images are deleted and container runtime is entirely pruned. 
1. Kubernetes node is deleted from the Kubernetes cluster.

**Warning**: To prevent the loss of the modified CoreDNS configuration (in case the configuration was modified by the cloud administrator and etc) - you must specify this CoreDNS configuration in the `cluster.yaml`, otherwise the configuration will be lost.

### Configuring Remove Node Procedure

The procedure accepts required positional argument with the path to the procedure inventory file.

The JSON schema for procedure inventory is available by [URL](../kubemarine/resources/schemas/remove_node.json?raw=1).
For more information, see [Validation by JSON Schemas](Installation.md#inventory-validation).

To remove nodes, it is possible to use the configuration format similar to installation or adding. For more information, refer to [Kubemarine Inventory Nodes](Installation.md#nodes) section in _Kubemarine Installation Procedure_.

For example:

```yaml
nodes:
  - name: "lb"
    internal_address: "192.168.0.1"
    roles: ["balancer"]
  - name: "control-plane"
    internal_address: "192.168.0.2"
    roles: ["control-plane"]
```

However, it is allowed to use a simple configuration, where only the node `name` is present.

For example:

```yaml
nodes:
  - name: "lb"
  - name: "control-plane"
```

### Remove Node Tasks Tree

The `remove_node` procedure executes the following sequence of tasks:

* loadbalancer
  * remove
    * haproxy
    * keepalived
  * configure
    * haproxy
    * keepalived
* update
  * etc_hosts
  * coredns
  * plugins
* remove_kubernetes_nodes
* overview

## Operating System Migration

To change the operating system on an already running cluster:

1. Start Kubemarine IAAS and PAAS checks, make sure that the cluster is operating correctly and without any problems.
1. Backup the entire cluster and virtual machine snapshots.
1. Run the Remove node procedure for the node you want to migrate with an old OS.
1. Backup/restore/migrate service-specific data from the old node to a new one.
1. Run the Add node procedure for the node you are migrating with the new OS. The old node can be redeployed with the new OS, or another with a new OS used.
1. Start Kubemarine IAAS and PAAS checks, make sure all services, pods, entire cluster are healthy and running correctly.
1. If something is not functioning correctly in the cluster, manually correct it before resuming.
1. Start the migration for the next node, and migrate all the remaining nodes.
1. After the migration finished, manually replace all OS-specific information in your `cluster.yaml`: repositories, packages, and associations, if any. Also pay attention to their versions. In further procedures, use only the new inventory instead of the old one.

**Note**: It is possible to migrate the OS removing/adding groups of nodes, not only for a single node. However, be careful with the selected group of nodes - incorrectly selected nodes for removal or their amount can damage the cluster or lead it to an unusable state. Select the nodes at your discretion.

**Warning**: It is necessary to complete the procedure and completely migrate all nodes to a single operating system. The cluster and services can exist on different operating systems, but if you need to immediately perform any maintenance procedure, Kubemarine does not allow you to do this, since the cluster is in an inconsistent state with another maintenance procedure not yet completed.

**Warning**: In case when you use custom associations, you need to specify them simultaneously for all types of operating systems. For more information, refer to the [associations](Installation.md#associations) section in the _Kubemarine Installation Procedure_.

## Manage PSP Procedure

The manage PSP procedure allows you to change PSP configuration on an already installed cluster. Using this procedure, you can:
* Add/delete custom policies
* Enable/disable OOB policies
* Enable/disable admission controller 

Manage PSP procedure works as follows:
1. During this procedure the custom policies specified for deletion are deleted.
   Then the custom policies specified for addition are added.
2. If OOB policies are reconfigured or admission controller is reconfigured, then all OOB policies are recreated
   as configured in the `cluster.yaml` and `procedure.yaml`. The values from `procedure.yaml` take precedence.
   If admission controller is disabled, then all OOB policies are deleted without recreation.
3. If the admission controller is reconfigured in `procedure.yaml`, then `kubeadm` configmap and `kube-apiserver` manifest is updated accordingly. 
4. All Kubernetes nodes are `drain-uncordon`ed one-by-one and all daemon-sets are restarted to restart all pods (except system) in order to re-validate pods specifications.

### Configuring Manage PSP Procedure

The procedure accepts required positional argument with the path to the procedure inventory file.

The JSON schema for procedure inventory is available by [URL](../kubemarine/resources/schemas/manage_psp.json?raw=1).
For more information, see [Validation by JSON Schemas](Installation.md#inventory-validation).

To manage PSPs on existing cluster, use the configuration similar to PSP installation, except the
`custom-policies` is replaced by `add-policies` and `delete-policies` as follows:

```yaml
psp:
  pod-security: enabled/disabled
  oob-policies:
    default: enabled/disabled
    host-network: enabled/disabled
    anyuid: enabled/disabled
  add-policies:
    psp-list: []
    roles-list: []
    bindings-list: []
  delete-policies:
    psp-list: []
    roles-list: []
    bindings-list: []
```

For example, if admission controller is disabled on existing cluster and you want to enable it, without enabling
`host-network` OOB policy, you should specify the following in the `procedure.yaml` file:

```yaml
psp:
  pod-security: enabled
  oob-policies:
    host-network: disabled
```

To configure `add-policies` and `delete-policies`, use the configuration format similar to `custom-policies`. For more information, refer to the [Configuring Custom Policies](Installation.md#configuring-custom-policies) section in the _Kubemarine Installation Procedure_.

**Note**: The OOB plugins use OOB policies, so disabling OOB policy breaks some OOB plugins. 
To avoid this, you need to specify custom policy and bind it using `ClusterRoleBinding` to the `ServiceAccout` plugin.

### Manage PSP Tasks Tree

The `manage_psp` procedure executes the following sequence of tasks:

1. check_inventory
1. delete_custom
2. add_custom
3. reconfigure_oob
4. reconfigure_plugin
5. restart_pods

## Manage PSS Procedure

The manage PSS procedure allows:
* enable/disable PSS
* change default settings
* change exemptions
* set PSS labels on namespaces

### Configure Manage PSS Procedure

The procedure accepts required positional argument with the path to the procedure inventory file.

The JSON schema for procedure inventory is available by [URL](../kubemarine/resources/schemas/manage_pss.json?raw=1).
For more information, see [Validation by JSON Schemas](Installation.md#inventory-validation).

To manage PSS on existing cluster one should configure `procedure.yaml` similar the following:

```yaml
pss:
  pod-security: enabled/disabled
  defaults:
    enforce: privileged/baseline/restricted
    enforce-version: latest
    audit: privileged/baseline/restricted
    audit-version: latest
    warn: privileged/baseline/restricted
    warn-version: latest
  exemptions:
    usernames: ["example-user1", "example-user2"]
    runtimeClasses: ["example-class-1", "example-class-2"]
    namespaces: ["kube-system", "example-namespace-1", "example-namespace-2"]
  namespaces:
    - example-namespace-1
    - example-namespace-2:
        enforce: privileged/baseline/restricted
        enforce-version: latest
        audit: privileged/baseline/restricted
        audit-version: latest
        warn: privileged/baseline/restricted
        warn-version: latest
    - example-namespace-3
    - example-namespace-4
  namespaces_defaults:
    enforce: privileged/baseline/restricted
    enforce-version: latest
    audit: privileged/baseline/restricted
    audit-version: latest
    warn: privileged/baseline/restricted
    warn-version: latest
restart-pods: false
```

The following sections are optional: `defaults`, `exemptions`, `namespaces`. The `namespaces` section describes the list of 
namespaces that will be labeled during the maintenance procedure. The `restart-pods` options enforce restart all pods in cluster.
The `namespaces_defaults` option is useful for bulk labels setting. In case of `namespaces_defaults` is set labels in `namespaces` 
section may be omitted. The labels from `namespaces_defaults` will be applied on namespaces list from `namespaces` then any labels 
from particular namespaces will be applied.

**Warnings**:
* Be careful with the `exemptions` section it may cause cluster instability.
* Do not delete `kube-system` namespace from `exemptions` list without strong necessity.
* The PSS labels in namespaces for Kubemarine supported plugins ('nginx-ingress-controller', 'local-path-provisioner', 
'kubernetes-dashboard', and 'calico' (calico-apiserver)) are managed automatically.
They are deleted during the procedure in case of using `pod-security: disabled`, and changed accordingly in case `pss.defaults.enforce` is changed.
* Be careful with the `restart-pods: true` options it drains nodes one by one and may cause cluster instability. The best way to 
restart pods in cluster is a manual restart according to particular application. The restart procedure should consider if the 
application is stateless or stateful. Also shouldn't use `restart-pod: true` option if [Pod Disruption Budget](https://kubernetes.io/docs/tasks/run-application/configure-pdb/) is configured.
* Pay attention to the fact that for Kubernetes versions higher than v1.23 the PSS option implicitly enabled by default in 
`kube-apiserver` [Feature Gates](https://kubernetes.io/docs/reference/command-line-tools-reference/feature-gates/). Therefor all PSS labels on namespaces should be deleted during the maintenance procedure so as not to face unpredictable cluster behavior.

### Manage PSS Tasks Tree

The `manage_pss procedure executes the following sequence of tasks:

1. check_inventory
2. delete_default_pss
3. apply_default_pss
4. restart_pods

## Reboot Procedure

This procedure allows you to safely reboot all nodes in one click. By default, all nodes in the cluster are rebooted. Gracefully reboot is performed only if installed Kubernetes cluster is detected on nodes. You can customize the process by specifying additional parameters.

### Reboot Procedure Parameters

The procedure accepts optional positional argument with the path to the procedure inventory file.
You can find description and examples of the accepted parameters in the next sections.

The JSON schema for procedure inventory is available by [URL](../kubemarine/resources/schemas/reboot.json?raw=1).
For more information, see [Validation by JSON Schemas](Installation.md#inventory-validation).

#### graceful_reboot Parameter

The parameter allows you to forcefully specify what type of reboot to perform. Possible values:

* `False` - All cluster nodes are forced to restart at the same time and immediately. This is a quick operation. If you have a cluster installed, this causes it to be temporarily unavailable.
* `True` - All cluster nodes are rebooted, pods drained to other nodes and rebooted one after another, after which the pods are scheduled back to the nodes. This is a very long operation. This procedure should not cause the cluster to be unavailable, but may slow down some applications in the cluster.

Example:

```yaml
graceful_reboot: False
```

#### nodes Parameter

This parameter allows you to specify which nodes should be rebooted. Other nodes are not affected. In this parameter, you must specify a list of node names, as is follows:

```yaml
nodes:
  - name: control-plane-1
  - name: control-plane-2
  - name: control-plane-3
```


## Certificate Renew Procedure

The `cert_renew` procedure allows you to renew some certificates on an existing Kubernetes cluster. 

For Kubernetes, most of the internal certificates could be updated, specifically: 
`apiserver`, `apiserver-etcd-client`, `apiserver-kubelet-client`, `etcd-healthcheck-client`, `etcd-peer`, `etcd-server`,
`admin.conf`, `controller-manager.conf`, `scheduler.conf`, `front-proxy-client`. 
Certificate used by `kubelet.conf` by default is updated automatically by Kubernetes, 
link to Kubernetes docs regarding `kubelet.conf` rotation: https://kubernetes.io/docs/tasks/tls/certificate-rotation/#understanding-the-certificate-rotation-configuration.

**Note**: Each time you run this procedure, kubelet and all control plane containers are restarted.

**Note**: CA certificates cannot be updated automatically and should be updated manually after 10 years.

**Note**: The `cert_renew` procedure does not renew the `kubelet` server certificate. To avoid this, implement the changes mentioned in the [Kubelet Server Certificate Approval](#kubelet-server-certificate-approval) section.

For nginx-ingress-controller, the config map along with the default certificate is updated with a new certificate and key. The config map update is performed by plugin re-installation.

For Calico, the certificate is updated for the Calico API server.

The `cert_renew` procedure also allows you to monitor Kubernetes internal certificates expiration status.

### Configuring Certificate Renew Procedure

The procedure accepts required positional argument with the path to the procedure inventory file.
You can find description and examples of the accepted parameters in the next sections.

The JSON schema for procedure inventory is available by [URL](../kubemarine/resources/schemas/cert_renew.json?raw=1).
For more information, see [Validation by JSON Schemas](Installation.md#inventory-validation).

#### Configuring Certificate Renew Procedure for nginx-ingress-controller

To update the certificate and key for `nginx-ingress-controller`, use the following configuration:

```yaml
nginx-ingress-controller:
  data:
    cert: |
      -----BEGIN CERTIFICATE-----
      ...(skipped)...
      -----END CERTIFICATE-----
    key: |
      -----BEGIN RSA PRIVATE KEY-----
      ...(skipped)...
      -----END RSA PRIVATE KEY-----
```

Similar to the plugin configuration, you can either use the data format or the paths format.
For more information about these formats, refer to the [nginx-ingress-controller](Installation.md#nginx-ingress-controller) section in the _Kubemarine Installation Procedure_.

#### Configuring Certificate Renew Procedure for Calico

To update the certificate and key for `calico` API server, use the following configuration:

```yaml
calico:
  apiserver:
    renew: true
```

**Note**: The certificate update procedure follows the default Calico API server installation procedure.
If you have custom Calico installation steps in the `plugins.calico.installation.procedures` section of the `cluster.yaml`
that in particular renews the certificate in a custom way,
you may want to repeat the corresponding steps using [Plugins Reinstallation](Installation.md#plugins-reinstallation).

#### Configuring Certificate Renew Procedure for Kubernetes Internal Certificates

To update internal Kubernetes certificates you can use the following configuration:
```yaml
kubernetes:
  cert-list:
    - apiserver
    - apiserver-etcd-client
    - apiserver-kubelet-client
    - etcd-healthcheck-client
    - etcd-peer
    - etcd-server
    - admin.conf
    - controller-manager.conf
    - scheduler.conf
    - front-proxy-client
```
Above list contains all possible certificates for update. You can pick all or some of them, as you need.
Alternatively to specifying the full list, you can use shorter form:
```yaml
kubernetes:
  cert-list:
    - all
```

### Certificate Renew Tasks Tree

The `cert_renew` procedure executes the following sequence of tasks: 

1. kubernetes
2. nginx_ingress_controller
3. calico
4. certs_overview

## Cri Migration Procedure

The `migrate_cri` procedure allows you to migrate from Docker to Containerd.

**Note**: This procedure consults `/etc/fstab` to see if separate disk is used for docker directory `/var/lib/docker`.
If there is such disk, it will be **cleared** and re-mounted to `/var/lib/containerd`.

**Warning**: This procedure works only in one direction.

**Warning**: If for some reason, the migration to Containerd has been executed on an environment where Containerd was already used as Cri, Kubernetes dashboard may be unavailable. To resolve this issue, restart the pods of the ingress-nginx-controller service.

**Warning**: The migration procedure removes the docker daemon from all nodes in the cluster.

### Procedure Execution Steps

This procedure includes the following steps:
1. Verify and merge all the specified parameters into the inventory.
2. Install and configure containerd.
3. Install crictl.
4. Implement the following steps on each control-plane and worker node by node:
    1. Drain the node.
    2. Update configurations on the node for migration to containerd.
    3. Move the pods on the node from the docker's containers to those of containerd.
    4. Uncordon the node.

**Warning**: Before starting the migration procedure, verify that you already have the actual cluster.yaml structure. The services.docker scheme is deprecated. 

### migrate_cri Parameters

The procedure accepts required positional argument with the path to the procedure inventory file.
You can find description and examples of the accepted parameters in the next sections.

The JSON schema for procedure inventory is available by [URL](../kubemarine/resources/schemas/migrate_cri.json?raw=1).
For more information, see [Validation by JSON Schemas](Installation.md#inventory-validation).

The following sections describe the `migrate_cri` parameters.

#### cri Parameter

In this parameter, you should specify `containerRuntime: containerd` and the configuration for it.

**Note**: This parameter is mandatory. An exception is raised if the parameter is absent.

Example for CLI:

```yaml
cri:
  containerRuntime: containerd
  containerdConfig:
    plugins."io.containerd.grpc.v1.cri":
      sandbox_image: registry.k8s.io/pause:3.2
    plugins."io.containerd.grpc.v1.cri".registry.mirrors."artifactory.example.com:5443":
      endpoint:
      - https://artifactory.example.com:5443
```

#### yum-repositories Parameter

This parameter allows you to specify a new repository from where containerd could be downloaded.

**Note**: This parameter is optional.

Example:

```yaml
yum:
  repositories:
    test-repo:
      name: repo-name
      enabled: 1
      gpgcheck: 0
      baseurl: http://example.com/misc/epel/7/x86_64/
```

#### packages-associations Parameter

This parameter allows you to specify an association for containerd, thus you could set a concrete version which should be installed from the allowed repositories.

**Note**: This parameter is optional.

Example:

```yaml
packages:
  associations:
    containerd:
      executable_name: 'containerd'
      package_name: 'containerd.io-1.4.*'
      service_name: 'containerd'
      config_location: '/etc/containerd/config.toml'
```

#### thirdparties Parameter

This parameter allows you to specify the link to a concrete version of a crictl third-party. In the absence of this parameter, crictl is downloaded from Github/registry in case you ran the procedure from CLI. 

**Note**: This parameter is optional.

Example:

```yaml
thirdparties:
  /usr/bin/crictl.tar.gz:
    source: https://github.com/kubernetes-sigs/cri-tools/releases/download/v1.20.0/crictl-v1.20.0-linux-amd64.tar.gz
```

## Admission Migration Procedure

Since Kubernetes v1.20 Pod Security Policy (PSP) has been deprecated and will be delete in Kubernetes 1.25 the migration procedure 
from PSP to  another solution is very important. Kubemarine supports Pod Security Standards (PSS) by default as a replacement PSP.
The most important step in the procedure is to define the PSS profiles for particular namespace. PSS has only three feasible options:
`privileged`, `baseline`, `restricted` that should be matched with PSP. It's better to use more restrictive the PSS profile 
for namespace. For proper matching see the following articles:
* [Migrate from PodSecurityPolicy](https://kubernetes.io/docs/tasks/configure-pod-container/migrate-from-psp/)
* [Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)

**Notes**: 
* Kubemarine predefined PSP such as 'oob-anyuid-psp', 'oob-host-network-psp', 'oob-privileged-psp' match with 'privileged' PSS profile and 'oob-default-psp' matches with 'restricted' PSS profile.
* Before running the migration procedure, be sure that all applications in Kubernetes cluster match with prerequisites:
[Application prerequisites](https://github.com/Netcracker/KubeMarine/blob/main/documentation/Installation.md#application-prerequisites)
* One of the ways to check if the pods in a particular namespace are matched with the PSS profile is that the `pod-security.kubernetes.io/enforce` label in the namespace should be set to `privileged`, whereas the `pod-security.kubernetes.io/warn` and `pod-security.kubernetes.io/audit` labels should be set to `restricted` or `baseline`. When the pods are up and running in the namespace, the audit messages and namespace events can be checked. Any violation of the `restricted` profile is reflected in these messages. The next step is to rework the pods that violate the PSS profile and repeat the procedure.


### Procedure Execution Steps

1. Verify that Kubernetes cluster has version v1.23+
2. Match the PSP permission to PSS and define the PSS profile for each namespace in cluster according to the notes above. 
3. Run the `manage_psp` procedure with `pod-security: disabled` option, ensure `admission: psp` is set in `cluster.yaml` preliminary. The example of `cluster.yaml` part is the following:
```yaml
...
rbac:
  admission: psp
  psp:
    pod-security: enabled
...
```

The example of `procedure.yaml` is the following:
```yaml
psp:
  pod-security: disabled
```

4. Verify if the applications in the cluster work properly.
5. Set the `admission: pss` options in `cluster.yaml`. An example of the `cluster.yaml` part is as follows:

```yaml
...
rbac:
  admission: pss
  pss:
    pod-security: disabled
...
```

6. Create the `procedure.yaml` for `migrate_pss` and fill in `namespaces` subsection in `pss` section in procedure file. The example of `procedure.yaml` is the following:

```yaml
pss:
  pod-security: enabled
  namespaces:
    - namespace_1
    - namespace_2:
        enforce: "baseline"
    - namespace_3
  namespaces_defaults:
    enforce: "privileged"
    enforce-version: latest
restart-pods: false
```

7. Run the `manage_pss` procedure with `restart-pods: true` option if it is applicable for solution
8. Restart pods in all namespaces if `restart-pods: false` option was used on previous step
9. Verify if the applications in cluster work properly

It's possible to switch off `PSS` on dev environment for some reason. In this case migration procedure become shorter and steps #6,7,8 should be skipped.

# Procedure Execution

The following sections describe the execution of procedures using CLI. 

## Procedure Execution from CLI

The command line executive for maintenance procedures has the same parameters as the installation executive. For more details, refer to the [Installing Kubernetes Using CLI](Installation.md#installation-of-kubernetes-using-cli) section in _Kubemarine Installation Procedure_.

The following features described in the _Kubemarine Installation Procedure_ are also available for maintenance procedures:

* [Custom Inventory File Location](Installation.md#custom-inventory-file-location)
* [Tasks List Redefinition](Installation.md#tasks-list-redefinition)
* [Ansible Inventory](Installation.md#ansible-inventory)
* [Dump Files](Installation.md#dump-files)

For maintenance procedures, it is mandatory to provide procedure-specific **procedure.yaml** configuration as positional argument, in addition to an ordinary **cluster.yaml** cluster inventory. You can redefine the tasks list for execution/exclusion according to the selected procedure Tasks Tree. For more information, refer to the [Tasks List Redefinition](Installation.md#tasks-list-redefinition) section in _Kubemarine Installation Procedure_.

Also it is possible to get the list of supported options and their meaning by executing the maintenance procedure with `--help` flag.

**Note**: After the maintenance procedure is completed, you can find the updated inventory files in place of the old ones. After each procedure, the old version of **cluster.yaml** is backed up to `dump/cluster.yaml_mm-dd-yyyy-hh:MM:ss`.

An example for running `add_node` procedure without the **cluster.yaml** definition is as follows:

```bash
kubemarine add_node procedure.yaml
```

It is used from the current location.

An example for running `remove_node` procedure with explicit **cluster.yaml** is as follows:

```bash
kubemarine remove_node procedure.yaml --config="${PATH_TO_CONFIG}/cluster.yaml"
``` 

An example for running the `add_node` procedure with overridden tasks is as follows:

```bash
kubemarine add_node procedure.yaml --tasks="deploy" --exclude="deploy.loadbalancer"
```

## Logging

Kubemarine has the ability to customize the output of logs, as well as customize the output to a separate file or graylog.
For more information, refer to the [Configuring Kubemarine Logging](Logging.md) guide.

## Inventory Preservation

The Kubemarine collects information about each `successful` procedure operation with the cluster and stores it on all master nodes under the following path:
```
/etc/kubemarine/procedure/`<timestamp_procedure-name>`/
```
The list of preserved information:
```yaml
cluster.yaml
version
dump/
  cluster.yaml
  cluster_initial.yaml
  procedure.yaml
  cluster_finalized.yaml
  cluster_precompiled.yaml
  procedure_parameters
```

Description of the following files:
* cluster.yaml - Input cluster inventory
* version -  Kubemarine version
* procedure_parameters - List of finished tasks


## Additional Parameters

The Kubernetes cluster has the following additional parameters.

### Grace Period and Drain Timeout

The `remove_node`, `upgrade`, and `migrate_kubemarine` (in some cases) procedures perform pods' draining before next actions. The pods' draining gracefully waits for the pods' migration to other nodes, before killing them. It is possible to modify the time to kill using the `grace_period` parameter in the **procedure.yaml** as follows (time in seconds):

```yaml
grace_period: 180
```

**Note**: To disable the `grace_period` parameter, simply set the value to "0".

Also, these procedures wait for the pods' killing. This waiting time also is configurable with the `drain_timeout` parameter in the **procedure.yaml** as follows (time in seconds):

```yaml
drain_timeout: 260
```

### Images Prepull

For the `add_nodes` and `upgrade` procedures, an images prepull task is available. This task prepulls images on specified nodes, but separates them on subgroups by 20 nodes per group, by default. This is required to avoid high load on the registry server. This value can be modified by setting the `prepull_group_size` parameter in the **procedure.yaml**, for example:

```yaml
prepull_group_size: 100
```

# Additional Procedures

The following Kubemarine procedures are available additionally: 
- `version`      Print current release version
- `do`           Execute shell command on cluster nodes

## Changing Calico Settings
	
Sometimes, during the operation you have to change the parameters of the Calico plugin. To do this, you can use the standard Kubemarine tools.
	
**Warning**: This procedure is performed on all nodes.
	
The parameters are changed using the command, **kubemarine install --config='file' --tasks=deploy.plugins**.
	
Before the installation, you have to change the yaml file responsible for the cluster deployment:
	
```
plugins:
  calico:
    install: true
    version: v3.10.1
	
```

## Data Encryption in Kubernetes

The following section describes the Kubernetes cluster capabilities to store and manipulate encrypted data.

### Enabling Encryption

ETCD as a Kubernetes cluster storage can interact with encrypted data. The encryption/decryption procedures are the part of `kube-apiserver` functionality.

An example of the `EncryptionConfiguration` file is as follows:

```yaml
apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
  - resources:
      - secrets
      - configmaps
    providers:
      - aesgcm:
          keys:
            - name: key1
              secret: c2VjcmV0IGlzIHNlY3VyZQ==
            - name: key2
              secret: dGhpcyBpcyBwYXNzd29yZA==
      - aescbc:
          keys:
            - name: key1
              secret: c2VjcmV0IGlzIHNlY3VyZQ==
            - name: key2
              secret: dGhpcyBpcyBwYXNzd29yZA==
      - secretbox:
          keys:
            - name: key1
              secret: YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=
      - identity: {}
```

It should be created preliminarily and placed in the `/etc/kubernetes/enc/` directory.

The next step is to enable the encryption settings in `kubeadm-config`: 
```yaml
data:
  ClusterConfiguration: |
    apiServer:
      ...
      extraArgs:
        ...
        encryption-provider-config: /etc/kubernetes/enc/enc.yaml
      extraVolumes:
      ...
      - hostPath: /etc/kubernetes/enc
        mountPath: /etc/kubernetes/enc
        name: enc
        pathType: DirectoryOrCreate
```

There is an `--encryption-provider-config` option that points to the `EncryptionConfiguration` file location. The `kube-apiserver` should have the following parts in the manifest yaml:

```yaml
...
spec:
  containers:
  - command:
    - kube-apiserver
     ...
    - --encryption-provider-config=/etc/kubernetes/enc/enc.yaml
      ...
    volumeMounts:
    - name: enc
      mountPath: /etc/kubernetes/enc
      readonly: true
       ...
  volumes:
  - name: enc
    hostPath:
      path: /etc/kubernetes/enc
      type: DirectoryOrCreate
```

In the above case, the `secrets` and `configmaps` are encrypted on the first key of the `aesgcm` provider, but the previously encrypted `secrets` and `configmaps` are decrypted on any keys of any providers that are matched. This approach allows to change both encryption providers and keys during the operation. The keys should be random strings in base64 encoding. `identity` is the default provider that does not provide any encryption at all.
For more information, refer to [https://kubernetes.io/docs/tasks/administer-cluster/encrypt-data/](https://kubernetes.io/docs/tasks/administer-cluster/encrypt-data/).

### Integration with External KMS

There is an encryption provider `kms` that allows using an external `Key Management Service` for the key storage, therefore the keys are not stored in the `EncryptionConfiguration` file, which is more secure. The `kms` provider needs to deploy a KMS plugin for further use.
The `Trousseau` KMS plugin is an example. It works through a unix socket, therefore `Trousseau` pods must be run on the same nodes as `kube-apiserver`. In case of using the KMS provider, the `EncryptionConfiguration` is as follows (`Vault` is a KMS):

```yaml
apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
  - resources:
      - secrets
      - configmaps
    providers:
      - kms:
          name: vaultprovider
          endpoint: unix:///opt/vault-kms/vaultkms.socket
          cachesize: 100
          timeout: 3s
      - identity: {}
```

Also, unix socket must be available for `kube-apiserver`:


```yaml
apiVersion: v1
kind: Pod
metadata:
  name: kube-apiserver
  namespace: kube-system
spec:
  containers:
  - command:
    volumeMounts:
    - mountPath: /opt/vault-kms/vaultkms.socket
      name: vault-kms
       ...
  volumes:
  - hostPath:
      path: /opt/vault-kms/vaultkms.socket
      type: Socket
    name: vault-kms
```

The environment variable `VAULT_ADDR` matches the address of the `Vault` service and `--listen-addr` argument points to KMS plugin unix socket in the following example:

```yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: vault-kms-provider
  namespace: kube-system
    ...
spec:
  template:
    spec:
      initContainers:
        - name: vault-agent
          image: vault
          securityContext:
            privileged: true
          args:
            - agent
            - -config=/etc/vault/vault-agent-config.hcl
            - -log-level=debug
          env:
            - name: VAULT_ADDR
              value: http://vault-adress:8200
               ...
      containers:
        - name: vault-kms-provider
          image: ghcr.io/ondat/trousseau:v1.1.3
          imagePullPolicy: Always
          args:
            - -v=5
            - --config-file-path=/opt/trousseau/config.yaml
            - --listen-addr=unix:///opt/vault-kms/vaultkms.socket
            - --zap-encoder=json
            - --v=3
```

For more information, refer to:
* [https://kubernetes.io/docs/tasks/administer-cluster/kms-provider/](https://kubernetes.io/docs/tasks/administer-cluster/kms-provider/)
* [https://github.com/ondat/trousseau/wiki/Trousseau-Deployment](https://github.com/ondat/trousseau/wiki/Trousseau-Deployment)

### Disabling Encryption

The first step of disabling encryption is to make the `identity` provider default for encryption. The enabling of `EncryptionConfiguration` should be similar to the following example:

```yaml
apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
  - resources:
      - secrets
      - configmaps
    providers:
      - identity: {}
      - aesgcm:
          keys:
            - name: key1
              secret: c2VjcmV0IGlzIHNlY3VyZQ==
            - name: key2
              secret: dGhpcyBpcyBwYXNzd29yZA==
      - aescbc:
          keys:
            - name: key1
              secret: c2VjcmV0IGlzIHNlY3VyZQ==
            - name: key2
              secret: dGhpcyBpcyBwYXNzd29yZA==
      - secretbox:
          keys:
            - name: key1
              secret: YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=
```

The next step is to replace all resources that were previously encrypted (e.g. `secrets`):

```console
# kubectl get secrets --all-namespaces -o json | kubectl replace -f -
```

It is then possible to remove encryption settings from the `kubeadm-config` configmap and `kube-apiserver` manifest.

### Maintenance and Operation Features

* Since the `/etc/kubernetes/enc/enc.yaml` file has keys, access to the file must be restricted. For instance:
```console
# chmod 0700 /etc/kubernetes/enc/
```

* The proper way for using encryption is to rotate the keys. The rotation procedure of the keys should take into consideration the fact that the `EncryptionConfiguration` file must be equal on each `control-plane` node. During the keys rotation procedure, some operation of getting the encrypted resources may be unsuccessful.
* The `kube-apiserver` has an `--encryption-provider-config-automatic-reload` option that allows applying a new `EncryptionConfiguration` without `kube-apiserver` reload.

* ETCD restore procedures should take into consideration the keys rotation, otherwise some data may be unavailable due to keys that were used for encryption and is not available after restoration. The backup procedure may include an additional step that renews all encrypted data before the ETCD backup. This approach decreases the security level for data in ETCD backup, but it prevents any inconvenience in the future. Another option is not to delete the keys from `env.yml` even if they are not used for encryption/decryption anymore.
* External services that interact with ETCD may stop working due to encryption enabling.

## Changing Cluster CIDR

There might be a situation when you have to change the pod network used in a cluster. The default `podSubnet` (`10.128.0.0/14` for IPv4 and `fd02::/48` for IPv6) may be inappropriate for some reason.

**Note**: Before proceeding, choose networks for `podSubnet` and `serviceSubnet` carefully, especially in case of IPv6 environments.
For example, it is not recommended to use networks from deprecated Site-Local scoped address prefix (fec0::/10). It is better to use the Unique Local Unicast range (fc00::/7).

If you are going to deploy a cluster from scratch, you can set custom `podSubnet` in the cluster.yaml:
```yaml
services:
  kubeadm:
    networking:
      podSubnet: '<NEW_NETWORK>'
```

If an existing cluster has to be updated with a new `podSubnet`, the following steps should be considered:

1. Check that any network security policies are disabled or new podSubnet is whitelisted. This is especially important for OpenStack environments.

2. Create an _ippool_ for new podSubnet:
```console
# cat <<EOF | calicoctl apply -f -
apiVersion: projectcalico.org/v3
kind: IPPool
metadata:
  name: new-ipv4-pool
spec:
  cidr: 10.228.0.0/14
  ipipMode: CrossSubnet
  natOutgoing: true
EOF
```

**Note**: The pod subnet mask size for a node cannot be greater than 16, more than the cluster mask size. This is especially important for IPv6 networks. The default `node-cidr-mask-size` for IPv6 is `64`. Therefore, you should use a cluster network mask not shorter than 48 or change the `node-cidr-mask-size` value respectively.

3. Disable the old _ippool_:
```console
# calicoctl get ippool -o yaml > ./ippools.yaml
# vi ippools.yaml
...
- apiVersion: projectcalico.org/v3
  kind: IPPool
  metadata:
    name: <OLD_IPPOOL_NAME>
  spec:
    disabled: true
...
# calicoctl apply -f ./ippools.yaml
```

4. Change the `podCIDR` parameter for all nodes:
```console
# export NODENAME=<NODENAME>
# kubectl get node ${NODENAME} -o yaml > ${NODENAME}.yaml
# sed -i "s~OLD_NODENET~NEW_NODENET~" ${NODENAME}.yaml
# kubectl delete node ${NODENAME} && kubectl create -f ${NODENAME}.yaml
``` 

5. Change `cluster-cidr` in kube-controller-manager manifest at all the master nodes:
```console
# vi /etc/kubernetes/manifests/kube-controller-manager.yaml
...
    - --cluster-cidr=10.228.0.0/14
...
```
After changing the manifest, the kube-controller-manager pod restarts automatically. Check that it has restarted successfully.

6. Edit the `calico-config` configmap, remove the old ippool name, and change the ip range:
```console
# kubectl -n kube-system edit cm calico-config
...
          "ipam": {"assign_ipv4": "true", "ipv4_pools": ["10.228.0.0/14"], "type": "calico-ipam"},
...
```

7. Edit the `calico-node` daemonset, and change the ip range:
```console
# kubectl -n kube-system edit ds calico-node
...
        - name: CALICO_IPV4POOL_CIDR
          value: 10.228.0.0/14
```
Check whether all `calico-node` pods have restarted successfully.

8. Change `clusterCIDR` in the `kube-proxy` configmap and restart kube-proxy:
```console
# kubectl -n kube-system edit cm kube-proxy
...
    clusterCIDR: 10.228.0.0/14
...
# kubectl -n kube-system rollout restart ds kube-proxy
```

9. Delete pods with ip addresses from the old ippool and check that they have restarted with addresses from the new pool successfully.

10. Update the `kubeadm-config` configmap with a new cluster network:
```console
# kubectl -n kube-system edit cm kubeadm-config
data:
  ClusterConfiguration: |
    ...
    networking:
      podSubnet: 10.228.0.0/14
```

11. Check that everything works properly and remove the old ippool if necessary.

## Kubelet Server Certificate Approval

The `kubelet` server certificate is self-signed by default, and is usually stored in the `/var/lib/kubelet/pki/kubelet.crt` file. To avoid using the self-signed `kubelet` server certificate, alter the `cluster.yaml` file in the following way:

```yaml
...
services:
  kubeadm_kubelet:
    serverTLSBootstrap: true
    rotateCertificates: true
  kubeadm:
    apiServer:
      extraArgs:
        kubelet-certificate-authority: /etc/kubernetes/pki/ca.crt
...
```

These settings enforce `kubelet` on each node of the cluster to request certificate approval (for `kubelet` server part) from the default Kubernetes CA and rotate certificate in the future. The `kube-apiserver` machinery does not approve certificate requests for `kubelet` automatically. They might be approved manually by the following commans. Get the list of certificate requests:

```
# kubectl get csr
NAME        AGE     SIGNERNAME                          REQUESTOR                 REQUESTEDDURATION    CONDITION
csr-2z6rv   12m     kubernetes.io/kubelet-serving       system:node:nodename-1    <none>               Pending
csr-424qg   89m     kubernetes.io/kubelet-serving       system:node:nodename-2    <none>               Pending
```

Approve the particular request:

```
kubectl certificate approve csr-424qg
```

These commands might be automated in several ways.

### Auto Approval CronJob

Basically, `CronJob` runs the approval command above for every CSR according to some schedule.

### Auto Approval Service

It is possible to install the kubelet-csr-approver service. For more information, refer to [[kubelet-csr-approver](https://github.com/postfinance/kubelet-csr-approver)](https://github.com/postfinance/kubelet-csr-approver). This service approves CSR automatically when a CSR is created according to several settings. It is better to restrict nodes' IP addresses (`providerIpPrefixes` option) and FQDN templates (providerRegex). For more information, refer to the official documentation.

# Common Practice

You should not run any containers on worker nodes that are not managed by `kubelet` so as not to break the `kube-scheduler` precision.
