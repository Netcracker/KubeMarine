This section describes the features and steps for performing maintenance procedures on the existing Kubernetes cluster.

- [Prerequisites](#prerequisites)
- [Basics](#basics)
- [Provided Procedures](#provided-procedures)
    - [Kubemarine Migration Procedure](#kubemarine-migration-procedure)
      - [Software Upgrade Patches](#software-upgrade-patches)
    - [Upgrade Procedure](#upgrade-procedure)
    - [Backup Procedure](#backup-procedure)
    - [Restore Procedure](#restore-procedure)
    - [Add Node Procedure](#add-node-procedure)
      - [Operating System Migration](#operating-system-migration)
    - [Remove Node Procedure](#remove-node-procedure)
    - [Reconfigure Procedure](#reconfigure-procedure)
    - [Manage PSS Procedure](#manage-pss-procedure)
    - [Reboot Procedure](#reboot-procedure)
    - [Certificate Renew Procedure](#certificate-renew-procedure)
- [Procedure Execution](#procedure-execution)
    - [Procedure Execution From CLI](#procedure-execution-from-cli)
    - [Logging](#logging)
    - [Inventory Preservation](#inventory-preservation)
    - [Additional Parameters](#additional-parameters)
      - [Grace Period and Drain Timeout](#grace-period-and-drain-timeout)
      - [Images Prepull](#images-prepull)
- [Additional Procedures](#additional-procedures)
    - [Changing Calico Settings](#changing-calico-settings)
    - [Data Encryption in Kubernetes](internal/Hardening.md#data-encryption-in-kubernetes)
    - [Changing Cluster CIDR](#changing-cluster-cidr)
    - [Kubelet Server Certificate Approval](#kubelet-server-certificate-approval)
- [Common Practice](#common-practice)
  - [Security Hardening Guide](#security-hardening-guide)
  - [Worker Nodes Should be Managed by Kubelet](#worker-nodes-should-be-managed-by-kubelet)

# Prerequisites

Before you start any maintenance procedure, you must complete the following mandatory steps:

1. Verify the environment for compliance with the prerequisites described in the [Kubemarine Installation Prerequisites](Installation.md#prerequisites) section in _Kubemarine Installation Procedure_.
1. Ensure that all the nodes are up, online, and healthy (except dead nodes, when you trying to remove them). This applies to the new nodes as well as the existing nodes.
1. If using custom registries, make sure they are online, accessible from nodes, and you are able to download images from the registries.
1. If using custom RPM repositories, make sure they are online, accessible from nodes, and you are able to perform repository updates.
1. Prepare the latest actual **cluster.yaml** that should contain information about the current cluster state. For more information, refer to the [Kubemarine Inventory Preparation](Installation.md#inventory-preparation) section in _Kubemarine Installation Procedure_.

   **Note**: If you provide an incorrect config file, it can cause unknown consequences. For more information, refer to [Basics](#basics). 

1. Prepare **procedure.yaml** file containing the configuration for the procedure that you are about to perform. Each procedure has its own configuration format. Read documentation below to fill procedure inventory data.

# Basics

According to the Kubemarine concept, `cluster.yaml` is a reflection of the Kubernetes cluster state.
Therefore, any changes on the cluster must be reflected in `cluster.yaml` in the corresponding section to be consistent with the cluster state.
This is an important practice even if the `cluster.yaml` section or option is applicable only for the installation procedure because the particular `cluster.yaml` can be used for the reinstallation or reproduction of some cases.
For the changes that cannot be reflected in `cluster.yaml`, the appropriate comments can be used.

The maintenance of the cluster can be done in two scenarios:

- It can be performed using some Kubemarine procedure. In this case, Kubemarine does its best to keep `cluster.yaml` and the cluster consistent to each other.
- The cluster can be reconfigured manually. In this case, the user should also manually reflect the changes in the `cluster.yaml`.

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
2. Containerd is upgraded.
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
It is because in this case, you take a full control over the thirdparties' versions and the defaults do not apply.

#### Packages Upgrade Patches

Patches that upgrade system packages have the following identifiers:
* `upgrade_cri` - It upgrades packages participating in the container runtime.
   For more information, refer to [Upgrade CRI Patch](#upgrade-cri-patch).
* `upgrade_haproxy` - It upgrades the Haproxy service on all balancers.
* `upgrade_keepalived` - It upgrades the Keepalived service on all balancers.

System packages such as containerd, haproxy, and keepalived are upgraded automatically as required.
You can influence the system packages' upgrade using the `packages` section as follows:

```yaml
upgrade:
  packages:
    associations:
      containerd:
        package_name:
          - 'containerd.io-1.6*'
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

After applying, this configuration is merged with the plugins' configuration contained in the current **cluster.yaml**.

**Note**: If you have changed images for any of the plugins in the **cluster.yaml**,
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
* The upgrade procedure only maintains upgrading from one `supported` version to the higher `supported` version.
  The target version must also be the latest patch version supported by Kubemarine.
  For example, upgrade is allowed from v1.26.7 to v1.26.11, or from v1.26.7 to v1.27.8, or from v1.26.7 to v1.28.4 through v1.27.8,
  but not from v1.26.7 to v1.27.1 as v1.27.1 is not the latest supported patch version of Kubernetes v1.27.

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

The script upgrades Kubernetes versions one-by-one. After each upgrade, the **cluster.yaml** is regenerated to reflect the actual cluster state. Use the latest updated **cluster.yaml** configuration to further work with the cluster.

Additionally, Kubemarine cleans up the `/etc/kubernetes/tmp` directory before the upgrade, where kubeadm stores the [backup files](https://kubernetes.io/docs/tasks/administer-cluster/kubeadm/kubeadm-upgrade/#recovering-from-a-failure-state)
during the upgrade. For this reason, only the backups for the latest upgrade through Kubemarine are placed here after the upgrade procedure.

**Note**: It is not recommended to use the backup files for rolling back after the upgrade because it can follow an inconsistent state 
for `cluster.yaml`. Use the Kubemarine [backup](#backup-procedure) and [restore](#restore-procedure) procedures instead of manual restoration.

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

#### Thirdparties Upgrade Section and Task

If the cluster is located in an isolated environment, it is possible to specify the custom paths to new thirdparties with the same syntax as in the **cluster.yaml** as shown in the following script:

```yaml
v1.30.1:
  thirdparties:
      /usr/bin/kubeadm:
        source: https://example.com/thirdparty.files/kubernetes/kubeadm/v1.30.1/bin/linux/amd64/kubeadm
      /usr/bin/kubelet:
        source: https://example.com/thirdparty.files/kubernetes/kubelet/v1.30.1/bin/linux/amd64/kubelet
      /usr/bin/kubectl:
        source: https://example.com/thirdparty.files/kubernetes/kubectl/v1.30.1/bin/linux/amd64/kubectl
      /usr/bin/calicoctl:
        source: https://example.com/thirdparty.files/projectcalico/calico/v3.27.3/calicoctl-linux-amd64
```

This configuration replaces the configuration contained in the current **cluster.yaml**.

#### Kubernetes Upgrade Task

This task is required to actually upgrade the Kubernetes cluster to the next version.
The upgrade is performed node-by-node.
On each node, containerd is upgraded, if required.
After all the pods are drained from the node, the node is upgraded and finally returned to the cluster for scheduling.

By default, node drain is performed using `disable-eviction=True` to ignore the PodDisruptionBudget (PDB) rules. If you want to enforce PDB rules during the upgrade, set `disable-eviction` to False. However, in this case, the upgrade may fail if you are unable to drain the node due of PDB rules. `disable-eviction` works only for upgrades on Kubernetes versions >= 1.18. 
An example configuration to enforce PDB rules is as follows:

```yaml
upgrade_plan:
  - v1.30.1

disable-eviction: False # default is True
```

The upgrade procedure is always risky, so you should plan a maintenance window for this procedure. If you encounter issues during the Kubernetes cluster upgrade, refer to the [Troubleshooting guide](Troubleshooting.md#failures-during-kubernetes-upgrade-procedure).

**Note**: During the upgrade, some or all internal Kubernetes certificates are updated. Do not rely on upgrade procedure to renew all certificates. Check the certificates' expiration using the `cert_renew` procedure for every 3 months independently of the upgrades
and plan the certificates' renewal accordingly.

#### CoreDNS Upgrade Task

This task is executed to restore the required CoreDNS configuration.

**Warning**: To prevent the loss of the modified CoreDNS configuration (in case the configuration was modified by the cloud administrator and etc) - you must specify this CoreDNS configuration in the `cluster.yaml`, otherwise the configuration will be lost.

#### Packages Upgrade Section and Task

This inventory section contains the configuration to upgrade custom and system packages, such as containerd.
The system packages are upgraded by default, if necessary.
You can influence the system packages' upgrade and specify custom packages for the upgrade/installation/removal using the `packages` section as follows:

```yaml
v1.30.1:
  packages:
    remove:
      - curl
    install:
      - unzip
      - policycoreutils-python
    upgrade:
      - openssl
    associations:
      containerd:
        package_name:
          - 'containerd.io-1.6*'
```

The requested actions for custom packages are performed in the `packages` task. The configuration from the procedure inventory replaces the configuration specified in the `cluster.yaml`. If you do not want to lose the packages specified in the `cluster.yaml`, then it is necessary to copy them to the procedure inventory.

By default, it is not required to provide information about system packages through associations.
They are upgraded automatically as required.
You can provide this information if you want to have better control over system packages' versions, such as containerd.
Also, you have to explicitly provide system packages' information if you have specified this information in the `cluster.yaml`.
It is because in this case, you take full control over the system packages and the defaults do not apply.
The provided configuration for system packages is merged with configuration in the `cluster.yaml`.

**Note**: The system packages are updated in separate tasks. For example, the container runtime (containerd) is upgraded during the Kubernetes upgrade.

**Note**: During the container runtime upgrade, the containers may be broken, so all containers on the node are deleted after the upgrade.
Kubernetes re-creates all the pod containers. However, your custom containers may be deleted, and you need to start them manually.

#### Plugins Upgrade Section and Task

This task is required to upgrade OOB plugins and specified user plugins.

The OOB plugins are upgraded automatically if the supported versions are changed for them.
For more information about the supported versions, refer to [Supported Versions](Installation.md#supported-versions).

The previously configured custom plugins are also re-installed if the effectively resolved inventory configuration is changed for them.
For example, they may depend on Kubernetes version using [Dynamic Variables](Installation.md#dynamic-variables).

You can also configure your own plugins for the upgrade as follows:

```yaml
v1.30.1:
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

You can also re-install custom or OOB plugins even without changes in the inventory configuration.

```yaml
v1.30.1:
  plugins:
    calico: {}
    example-plugin: {}
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
* Kubernetes resources (if it's configured in procedure.yaml)

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
* /etc/containerd/config.toml
* /etc/containerd/certs.d
* /etc/crictl.yaml
* /etc/ctr/kubemarine_ctr_flags.conf
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
* /root/.kube/config

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

The procedure can export any available Kubernetes resources from the cluster to yaml files. There are two types of resources - namespaced and non-namespaced. If you need to export resources, you can specify which ones you need. By default, **no** resources from **all** namespaces are exported.

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

If you do not specify `backup_plan.kubernetes`, the following configuration will be used:
```yaml
backup_plan:
  kubernetes:
    namespaced_resources:
      namespaces: all
      resources: []
    nonnamespaced_resources: []
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
* If there are some offline workers during the procedure, you should exclude `prepare.dns.etc_hosts` task and update `/etc/hosts` on new nodes manually.

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
* If you intend to add a new `balancer` node with VRRP IP, and have previously not configured the `vrrp_ips` section, you need to do the following preliminarily:
  * And the section to the main `cluster.yaml`.
  * If you already have balancers without VRRP IPs, reconfigure the balancers and DNS,
    for example, using `kubemarine install --tasks prepare.dns.etc_hosts,deploy.loadbalancer.haproxy.configure,deploy.loadbalancer.keepalived,deploy.coredns`.
* If you intend to add a new `balancer` node with VRRP IP, and have previously configured the `vrrp_ips` section in the `cluster.yaml` with the `hosts` subsection, then add the new balancer node to the `vrrp_ips.*.hosts` section in the `cluster.yaml` in the same way as the old balancer nodes if this new node has to share the same VRRP IP address.

For example, if you want `new-balancer-node-1` to be added to a subset of balancer nodes that share VRRP IP `192.168.0.100`:

```
vrrp_ips:
- hosts:
  - name: balancer-node-1
    priority: 254
  - name: balancer-node-2
    priority: 253
  - name: new-balancer-node-1
  ip: 192.168.0.100
```

It may be useful, if you have some VRRP IPs working at different subsets of balancer nodes. If you have one VRRP IP and all the balancer nodes must share it, just remove the `hosts` section from `vrrp_ips`.

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
    * etc_hosts
    * resolv_conf
  * package_manager
    * configure
    * disable_unattended_upgrades
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
* If there are some offline workers during the procedure, you should exclude `update.etc_hosts` task.

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

## Reconfigure Procedure

This procedure is aimed to reconfigure the cluster.

It is supposed to reconfigure the cluster as a generalized concept described by the inventory file.
Though, currently the procedure supports to reconfigure only Kubeadm-managed settings, and `services.sysctl`.
If you are looking for how to reconfigure other settings, consider the following:

- Probably some other [maintenance procedure](#provided-procedures) can do the task.
- Some [installation tasks](Installation.md#tasks-list-redefinition) can reconfigure some system settings without full redeploy of the cluster.

**Basic prerequisites**:

- Make sure to follow the [Basics](#basics).
- Before starting the procedure, consider making a backup. For more information, see the section [Backup Procedure](#backup-procedure).

### Reconfigure Procedure Parameters

The procedure accepts required positional argument with the path to the procedure inventory file.
You can find description and examples of the accepted parameters in the next sections.

The JSON schema for procedure inventory is available by [URL](../kubemarine/resources/schemas/reconfigure.json?raw=1).
For more information, see [Validation by JSON Schemas](Installation.md#inventory-validation).

**Common Considerations**

Each section from the procedure inventory is merged with the corresponding section in the main **cluster.yaml**,
and the related services are reconfigured based on the resulting inventory.

Additionally, it is possible to supply empty section describing a particular service for most services.
This does not introduce new changes in the **cluster.yaml**, but still triggers the reconfiguring,
and thus allows to make the cluster and the inventory consistent to each other.

Also, Kubemarine detects effectively changed settings of the services, if ones depend on the others, and reconfigures the dependent services accordingly.

#### Reconfigure Kubeadm

The following Kubeadm-managed sections can be reconfigured:

- `services.kubeadm.apiServer`
- `services.kubeadm.apiServer.certSANs`
- `services.kubeadm.scheduler`
- `services.kubeadm.controllerManager`
- `services.kubeadm.etcd.local.extraArgs`
- `services.kubeadm_kubelet`
- `services.kubeadm_kube-proxy`
- `services.kubeadm_patches`

For more information, refer to the description of these sections:

- [kubeadm](Installation.md#kubeadm)
- [kubeadm_kubelet](Installation.md#kubeadm_kubelet)
- [kubeadm_kube-proxy](Installation.md#kubeadm_kube-proxy)
- [kubeadm_patches](Installation.md#kubeadm_patches)

Example of procedure inventory that reconfigures all the supported sections:

<details>
  <summary>Click to expand</summary>

```yaml
services:
  kubeadm:
    apiServer:
      certSANs:
        - k8s-lb
      extraArgs:
        enable-admission-plugins: NodeRestriction,PodNodeSelector
        profiling: "false"
        audit-log-path: /var/log/kubernetes/audit/audit.log
        audit-policy-file: /etc/kubernetes/audit-policy.yaml
        audit-log-maxage: "30"
        audit-log-maxbackup: "10"
        audit-log-maxsize: "100"
    scheduler:
      extraArgs:
        profiling: "false"
    controllerManager:
      extraArgs:
        profiling: "false"
        terminated-pod-gc-threshold: "1000"
    etcd:
      local:
        extraArgs:
          heartbeat-interval: "1000"
          election-timeout: "10000"
  kubeadm_kubelet:
    protectKernelDefaults: true
  kubeadm_kube-proxy:
    conntrack:
      min: 1000000
  kubeadm_patches:
    apiServer:
      - groups: [control-plane]
        patch:
          max-requests-inflight: 500
      - nodes: [master-3]
        patch:
          max-requests-inflight: 600
    etcd:
      - nodes: [master-1]
        patch:
          snapshot-count: 110001
      - nodes: [master-2]
        patch:
          snapshot-count: 120001
      - nodes: [master-3]
        patch:
          snapshot-count: 130001
    controllerManager:
      - groups: [control-plane]
        patch:
          authorization-webhook-cache-authorized-ttl: 30s
    scheduler:
      - nodes: [master-2,master-3]
        patch:
          profiling: true
    kubelet:
      - nodes: [worker5]
        patch:
          maxPods: 100
      - nodes: [worker6]
        patch:
          maxPods: 200
```

</details>

The above configuration is merged with the corresponding sections in the main **cluster.yaml**,
and the related Kubernetes components are reconfigured based on the resulting inventory.

In this way it is not possible to delete some property,
allowing the corresponding Kubernetes component to fall back to the default behaviour.
This can be worked around by manual changing of the `cluster.yaml`
and running the `reconfigure` procedure with **empty** necessary section.
For example, you can delete `services.kubeadm.etcd.local.extraArgs.election-timeout` from **cluster.yaml**
and then run the procedure with the following procedure inventory:

```yaml
services:
  kubeadm:
    etcd: {}
```

**Note**: It is not possible to delete default parameters offered by Kubemarine.

**Note**: The mentioned hint to delete custom properties is not enough for `services.kubeadm_kube-proxy` due to existing restrictions of Kubeadm CLI tool.
One should additionally edit the `kube-proxy` ConfigMap and set the value that is considered the default.

**Note**: Passing of empty `services.kubeadm.apiServer` section reconfigures the `kube-apiserver`,
but does not write new certificate.
To **additionally** write new certificate, pass the desirable extra SANs in `services.kubeadm.apiServer.certSANs`.

**Restrictions**:

- Very few options of `services.kubeadm_kubelet` section can be reconfigured currently.
  To learn exact set of options, refer to the JSON schema.
- Some properties cannot be fully redefined.
  For example, this relates to some settings in `services.kubeadm.apiServer`.
  For details, refer to the description of the corresponding sections in the installation guide.

**Basic flow**:

If the procedure affects the particular set of Kubernetes components, all the components are reconfigured on each relevant node one by one.
The flow proceeds to the next nodes only after the affected components are considered up and ready on the reconfigured node.
Control plane nodes are reconfigured first.

Working `kube-apiserver` is not required to reconfigure control plane components (more specifically, to change their static manifests),
but required to reconfigure kubelet and kube-proxy.

### Reconfigure sysctl

The `reconfigure` procedure allows to supply new kernel parameters or change the existing ones
in the same format, and with the same caveats, as for the installation procedure.
For more information, refer to [sysctl](Installation.md#sysctl).

It is also possible to trigger reconfiguring using empty `services.sysctl` section:

```yaml
services:
  sysctl: {}
```

**Note**: kernel parameters can also be reconfigured using [patches](#append-patches).

**Warning**: Be careful with these settings, they directly affect the hosts operating system.

**Warning**: In comparison to the installation procedure, the new parameters are validated, but reboot is not scheduled.
To make sure that the new settings are preserved after reboot, perform the reboot using [Reboot Procedure](#reboot-procedure),
and run PaaS check, namely [232 Kernel Parameters Configuration](Kubecheck.md#232-kernel-parameters-configuration).

### Append Patches

It is possible to **append** new [patches](Installation.md#patches) to the main **cluster.yaml**, and trigger reconfiguring of the corresponding services.

The following sections are supported in the new patches:
- `services.sysctl`

Since the new patches are appended, the same settings have precedence in the last patch of the procedure inventory if overridden few times for the same node.

### Reconfigure Procedure Tasks Tree

The `reconfigure` procedure executes the following sequence of tasks:

- prepare
  - system
    - sysctl
- deploy
  - kubernetes
    - reconfigure

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

To manage PSS on existing cluster one should configure the **procedure.yaml** file similar the following:

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
* Pay attention to the fact that PSS is implicitly enabled by default (that is reflected in 
`kube-apiserver` [Feature Gates](https://kubernetes.io/docs/reference/command-line-tools-reference/feature-gates/) prior to Kubernetes v1.28).
Therefore, all PSS labels on namespaces should be deleted during the maintenance procedure so as not to face unpredictable cluster behavior.

### Manage PSS Tasks Tree

The `manage_pss` procedure executes the following sequence of tasks:

1. manage_pss
2. restart_pods

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
`admin.conf`, `super-admin.conf`, `controller-manager.conf`, `scheduler.conf`, `front-proxy-client`. 
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
    - super-admin.conf
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

# Common Practice

The common practice information is given below.

## Security Hardening Guide

For more information, refer to the [Security Hardening Guide](./internal/Hardening.md).

## Worker Nodes Should be Managed by Kubelet

You should not run any containers on worker nodes that are not managed by `kubelet` to avoid breaking the `kube-scheduler` precision.
