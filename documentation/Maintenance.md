This section describes the features and steps for performing maintenance procedures on the existing Kubernetes cluster.

- [Prerequisites](#prerequisites)
- [Provided Procedures](#provided-procedures)
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
    - [Migration Cri Procedure](#migration-cri-procedure)
- [Procedure Execution](#procedure-execution)
    - [Procedure Execution from CLI](#procedure-execution-from-cli)
    - [Logging](#logging)
    - [Additional Parameters](#additional-parameters)
      - [Grace Period and Drain Timeout](#grace-period-and-drain-timeout)
      - [Images Prepull](#images-prepull)
- [Additional procedures](#additional-procedures)
  - [Changing Calico Settings](#changing-calico-settings)
- [Common practice](#common-practice)

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

## Upgrade Procedure

**Warnings**: 
* API versions `extensions/v1beta1` and `networking.k8s.io/v1beta1` are not supported starting from Kubernetes 1.22 and higher. Need to update ingress to the new API `networking.k8s.io/v1`. More info: https://kubernetes.io/docs/reference/using-api/deprecation-guide/#ingress-v122
* Before starting the upgrade, make sure you make a backup. For more information, see the section [Backup Procedure](#backup-procedure).
* The upgrade procedure only maintains upgrading from one `supported` version to the next `supported` version. For example, from 1.18 to 1.20 or from 1.20 to 1.21.

The upgrade procedure allows you to automatically update Kubernetes cluster and its core components to a new version. To do this, you must specify the `upgrade_plan` in the procedure config, and fill in the new version of the Kubernetes cluster you want to upgrade to. For example:

```yaml
upgrade_plan:
  - v1.18.8
  - v1.19.3
```

**Note**: Be sure to check the version string format and do not forget to specify the letter `v` at the beginning of the string.

**Note**: It is not possible to skip minor Kubernetes versions. For example, to upgrade from 1.18.8 to 1.20.2, you have to first upgrade to the intermediate 1.19.3 version.

After starting the upgrade procedure, the script validates the correctness of the entered upgrade plan. If it contains issues, the update does not start, and a message with the problem description is displayed. If there are no errors, the following log with loaded update plan is displayed:

```yaml
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

Based on the example above, only the nodes `worker-10` and `worker-11` are updated, the rest are skipped.

**Note**: The nodes are excluded only from the Kubernetes upgrade. All other upgrade tasks like thirdparties, coredns, and so on are performed for all the nodes as they are. 

#### Nodes Saved Versions Before Upgrade

During the upgrade, a temporary file `/etc/kubernetes/nodes-k8s-versions.txt` is created on first master node that saves the state and versions of the nodes prior to the initial upgrade.
If the procedure fails and certain nodes for the upgrade are not manually specified, the saved versions of the nodes before the upgrade are used to determine the initial state of the nodes.
In case of a successful upgrade of a node, the information about it is deleted from the state file so as to not upgrade it again.
If the entire update cycle completes successfully, this temporary file is deleted, and in further upgrades it is generated anew.
At the same time, there may be situations when this file interferes with a normal upgrade - in this case, you can erase it or use manually specified nodes for the upgrade.

#### Thirdparties Upgrade Section and Task

If the cluster is located in an isolated environment, it is possible to specify the custom paths to new thirdparties with the same syntax as in the `cluster.yaml` as shown in the following script:

```yaml
v1.18.10:
  thirdparties:
      /usr/bin/kubeadm:
        source: https://example.com/thirdparty.files/kubernetes/kubeadm/v1.18.10/bin/linux/amd64/kubeadm
      /usr/bin/kubelet:
        source: https://example.com/thirdparty.files/kubernetes/kubelet/v1.18.10/bin/linux/amd64/kubelet
      /usr/bin/kubectl:
        source: https://example.com/thirdparty.files/kubernetes/kubectl/v1.18.10/bin/linux/amd64/kubectl
      /usr/bin/calicoctl:
        source: https://example.com/thirdparty.files/projectcalico/calicoctl/v3.14.1/calicoctl-linux-amd64
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

This inventory section contains the configuration to upgrade custom and system packages, such as docker, containerd, haproxy, and keepalived. The system packages are upgraded by default, if necessary. You can influence the system packages' upgrade and specify custom packages for the upgrade/installation/removal using the `packages` section as follows:

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
              destination_groups: ['master']
              destination_nodes: ['worker-1']
              apply_groups: None
              apply_nodes: ['master-1', 'worker-1']
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
* upgrade_containerd
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
    ├── master-1.tar.gz
    ├── master-2.tar.gz
    └── master-3.tar.gz
```

### Backup Procedure Parameters

**Note**: There are some examples located in [procedure.yaml examples](../examples/procedure.yaml).

By default, no parameters are required. However, if necessary, you can specify custom.

#### backup_location parameter

By default, the backup is placed into the workdirectory. However, if you want to specify a different location, you can specify it through `backup_location` parameter.
You can specify two types of path in it:
* The full path of the file, including the name. In this case, the file is saved to the specified path with the name you specified.
* Full path to the directory, without file name. In this case, the file is saved to the directory you specified, with the default name that contains the timestamp of the backup. For example:

```
  /home/centos/backup-{cluster_name}-20201214-162731.tar.gz
```

#### etcd parameters

You can specify custom parameters for ETCD snapshot creation task. The following options are available:

* `source_node` - the name of the node to create snapshot from. The node must be a master and have a ETCD data located on it.
* `certificates` - ETCD certificates for `etcdctl` connection to ETCD API. You can specify some certificates, or specify them all. You must specify the paths of certificates on the node from which the copy is made.

Parameters example:

```yaml
backup_plan:
  etcd:
    source_node: master-1
    certificates:
      cert: /etc/kubernetes/pki/etcd/server.crt
      key: /etc/kubernetes/pki/etcd/server.key
      cacert: /etc/kubernetes/pki/etcd/ca.crt
```

#### nodes parameter

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

#### kubernetes parameter

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

**Note**: There are some examples located in [procedure.yaml examples](../examples/procedure.yaml).

To start the procedure, you must mandatory specify `backup_location` parameter. Other parameters are optional, if necessary, you can also specify them.


#### backup_location parameter

You need to specify the required path to the file with the backup - the recovery is performed from it.

Example:

```
backup_location: /home/centos/backup-{cluster_name}-20201214-162731.tar.gz
```

#### etcd parameters

By default, ETCD restore does not require additional parameters, however, if required, the following are supported:

* image - the full name of the ETCD image, including the registry address. On its basis, the restoration is performed.
* certificates - ETCD certificates for `etcdctl` connection to ETCD API. You can specify some certificates, or specify them all. Certificates should be presented on all nodes.

#### thirdparties parameter

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
  * unpack
  * verify_backup_data
  * stop_cluster
* restore
  * thirdparties
* import
  * nodes
  * etcd
* reboot
* overview


## Add Node Procedure

The `add_node` procedure allows you to add new nodes to an existing Kubernetes cluster. It is possible to add several nodes at a time.
Each node can have different combination of roles.

The procedure works as shown in the following table:

|Case|Expected Result|Important Note|
|---|---|---|
|Add load balancer|A new load balancer is configured. If `vrrp_ip` is present, then all the Keepalived nodes are reconfigured and restarted.|Kubernetes and Keepalived installations should not start.|
|Add load balancer + Keepalived|A new load balancer is configured. Keepalived is installed and configured on all the load balancers.|Kubernetes installation should not start.|
|Add master|Kubernetes is installed only on a new node. A new master is added to the Kubernetes cluster, and all Haproxy nodes are reconfigured and restarted.|Haproxy installation should not start.|
|Add worker|Kubernetes is installed only on a new node. A new worker is added to the Kubernetes cluster, and all Haproxy nodes are reconfigured and restarted.|Haproxy installation should not start.|

Also pay attention to the following:

* Thirdparties, if any, should be installed only on new nodes. They should not be installed or updated on other nodes.
* Packages should be installed only on new nodes, and can be upgraded if the upgrade is available. Nodes that are already present in the cluster should not install or update packages.
* Configs should be generated and applied only to new nodes. The only exceptions are balancers and Keepalived.
* Plugins are not reinstalled.
* System configurations like `selinux`, `modprobe`, `sysctl`, and others should be verified and configured only on new nodes.
* Only new nodes can be rebooted.
* The file `/etc/hosts` is updated and uploaded to all nodes in the cluster.

**Note**: It is not possible to change a node's role by adding an existing node again with a new role. You have to remove the node and add it again.

**Warning**: To prevent the loss of the modified CoreDNS configuration (in case the configuration was modified by the cloud administrator and etc) - you must specify this CoreDNS configuration in the `cluster.yaml`, otherwise the configuration will be lost.

### Configuring Add Node Procedure

The `nodes` configuration format for specifying new nodes is the same as that of the installation procedure. For more information, refer to [Kubemarine Inventory Nodes](Installation.md#nodes) section in _Kubemarine Installation Procedure_.

The following example demonstrates the configuration of two nodes for adding:

```yaml
nodes:
  - name: "lb"
    internal_address: "192.168.0.1"
    roles: ["balancer"]
  - name: "master"
    internal_address: "192.168.0.2"
    roles: ["master"]
```

**Note**:

* The connection information for new nodes can be used from defaults as described in the [Kubemarine Inventory Node Defaults](Installation.md#node_defaults) section in _Kubemarine Installation Procedure_. If the connection information is not present by default, define the information in each new node configuration.
* You can add the `vrrp_ips` section to **procedure.yaml** if you intend to add the new `balancer` node and have previously not configured the `vrrp_ips` section.

### Add Node Tasks Tree

The `add_node` procedure executes the following sequence of tasks:

* prepare
  * check
    * sudoer
    * system
    * cluster_installation
  * dns
    * resolv_conf
    * etc_hosts
  * ntp
    * chrony
  * package_manager
    * configure_yum
    * manage_packages
  * system
    * setup_selinux
    * disable_firewalld
    * disable_swap
    * modprobe
    * sysctl
    * audit
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
    * init (as join)
    * wait_for_nodes
* overview

## Remove Node Procedure

The `remove_node` procedure removes nodes from the existing Kubernetes cluster. It is possible to remove several nodes with different combination of roles at a time. 

The procedure works as follows:

|Case|Expected Result|Important Note|
|---|---|---|
|Remove load balancer|Haproxy and Keepalived are disabled on removed nodes. Keepalived is reconfigured on all balancers.|Keepalived installation should not start.|
|Remove master|Kubernetes node is deleted from the cluster and Haproxy is reconfigured on all balancers.|Haproxy and Keepalived installation should not start. Keepalived should not be reconfigured.|
|Remove worker|Kubernetes node is deleted from the cluster and Haproxy is reconfigured on all balancers.|Haproxy and Keepalived installation should not start. Keepalived should not be reconfigured.|

Also pay attention to the following:

* If `vrrp_ip` is not used by any node after nodes removal, then the `vrrp_ip` is removed from **cluster.yaml**.
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

To remove nodes, it is possible to use the configuration format similar to installation or adding. For more information, refer to [Kubemarine Inventory Nodes](Installation.md#nodes) section in _Kubemarine Installation Procedure_.

For example:

```yaml
nodes:
  - name: "lb"
    internal_address: "192.168.0.1"
    roles: ["balancer"]
  - name: "master"
    internal_address: "192.168.0.2"
    roles: ["master"]
```

However, it is allowed to use a simple configuration, where only the node `name` is present.

For example:

```yaml
nodes:
  - name: "lb"
  - name: "master"
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
* update_etc_hosts
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
1. After the migration finished, manually replace all OS-specific information in your `cluster.yaml`: repositories, packages, associations, if any. Also pay attention to their versions. In further procedures, use only the new inventory instead of the old one.

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
4. All kubernetes nodes are `drain-uncordon`ed one-by-one and all daemon-sets are restarted to restart all pods (except system) in order to re-validate pods specifications.

### Configuring Manage PSP Procedure

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

1. delete_custom
2. add_custom
3. reconfigure_oob
4. reconfigure_plugin
5. restart_pods

## Manage PSP Procedure

The manage PSS procedure allows:
* enable/disable PSS
* change default settings
* change exemption

### Configure Manage PSS Procedure

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
    example-namespace-2:
      enforce: "baseline"
      version: latest
```

The following sections are optionals: `defaults`, `exemptions`, `namespaces`. The `namespaces` section describes the list of 
namespaces that will be labled during the maintenance procedure.

**Warnings**
Be careful with `exemption` section it may cause cluster instability.
Do not delete `kube-system` namespace from `exemptions` list without strong necessity.


## Reboot Procedure

This procedure allows you to safely reboot all nodes in one click. By default, all nodes in the cluster are rebooted. Gracefully reboot is performed only if installed Kubernetes cluster is detected on nodes. You can customize the process by specifying additional parameters.

### graceful_reboot parameter

The parameter allows you to forcefully specify what type of reboot to perform. Possible values:

* `False` - All cluster nodes are forced to restart at the same time and immediately. This is a quick operation. If you have a cluster installed, this causes it to be temporarily unavailable.
* `True` - All cluster nodes are rebooted, pods drained to other nodes and rebooted one after another, after which the pods are scheduled back to the nodes. This is a very long operation. This procedure should not cause the cluster to be unavailable, but may slow down some applications in the cluster.

Example:

```yaml
graceful_reboot: False
```

### nodes parameter

This parameter allows you to specify which nodes should be rebooted. Other nodes are not affected. In this parameter, you must specify a list of node names, as is follows:

```yaml
nodes:
  - name: master-1
  - name: master-2
  - name: master-3
```


## Certificate Renew Procedure

The `cert_renew` procedure allows you to renew some certificates on an existing Kubernetes cluster. 

For kubernetes most of the internal certificates could be updated, specifically: 
`apiserver`, `apiserver-etcd-client`, `apiserver-kubelet-client`, `etcd-healthcheck-client`, `etcd-peer`, `etcd-server`,
`admin.conf`, `controller-manager.conf`, `scheduler.conf`, `front-proxy-client`. 
Certificate used by `kubelet.conf` by default is updated automatically by kubernetes, 
link to kubernetes docs regarding `kubelet.conf` rotation: https://kubernetes.io/docs/tasks/tls/certificate-rotation/#understanding-the-certificate-rotation-configuration.

**Note**: Serving kubelet certificate `kubelet.crt` is updated forcefully by this procedure each time it runs.

**Note**: Each time you run this procedure, kubelet and all control plane containers are restarted.

**Note**: CA certificates cannot be updated automatically and should be updated manually after 10 years.

For nginx-ingress-controller, the config map along with the default certificate is updated with a new certificate and key. The config map update is performed by plugin re-installation.

The `cert_renew` procedure also allows you to monitor kubernetes internal certificates expiration status.

### Configuring Certificate Renew Procedure

#### Configuring Certificate Renew Procedure For nginx-ingress-controller
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

#### Configuring Certificate Renew Procedure For Kubernetes Internal Certificates
To update internal kubernetes certificates you can use the following configuration:
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
3. certs_overview

## Migration Cri Procedure

The `migrate_cri` procedure allows you to migrate from Docker to Containerd.

**Note**: This procedure consults `/etc/fstab` to see if separate disk is used for docker directory `/var/lib/docker`.
If there is such disk, it will be **cleared** and re-mounted to `/var/lib/containerd`.

**Warning**: This procedure works only in one direction.

**Warning**: If for some reason, the migration to Containerd has been executed on an environment where Containerd was already used as Cri, Kubernetes dashboard may be unavailable. To resolve this issue, restart the pods of the ingress-nginx-controller service.

**Warning** The migration procedure removes the docker daemon from all nodes in the cluster.

### migrate_cri parameters

The following sections describe the `migrate_cri` parameters.

#### cri parameter

In this parameter, you should specify `containerRuntime: containerd` and the configuration for it.

**Note**: This parameter is mandatory. An exception is raised if the parameter is absent.

Example for CLI:

```yaml
cri:
  containerRuntime: containerd
  containerdConfig:
    plugins."io.containerd.grpc.v1.cri":
      sandbox_image: k8s.gcr.io/pause:3.2
    plugins."io.containerd.grpc.v1.cri".registry.mirrors."artifactory.example.com:5443":
      endpoint:
      - https://artifactory.example.com:5443
```

#### yum-repositories parameter

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

#### packages-associations parameter

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

#### thirdparties parameter

This parameter allows you to specify the link to a concrete version of a crictl third-party. In the absence of this parameter, crictl is downloaded from Github/registry in case you ran the procedure from CLI. 

**Note**: This parameter is optional.

Example:

```yaml
thirdparties:
  /usr/bin/crictl.tar.gz:
    source: https://github.com/kubernetes-sigs/cri-tools/releases/download/v1.20.0/crictl-v1.20.0-linux-amd64.tar.gz
```


### Procedure Execution Steps

1. Verify and merge all the specified parameters into the inventory.
2. Install and configure containerd and podman.
3. Install crictl.
4. Implement the following steps on each master and worker node by node. 
    1. Drain the node.
    2. Update configurations on the node for migration to containerd.
    3. Move the pods on the node from the docker's containers to those of containerd.
    4. Uncordon the node.

**Warning**: Before starting the migration procedure, verify that you already have the actual claster.yaml structure. The services.docker scheme is deprecated. 

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


## Additional Parameters

The Kubernetes cluster has the following additional parameters.

### Grace Period and Drain Timeout

The `remove_nodes` and `upgrade` procedures perform pods' draining before next actions. The pods' draining gracefully waits for the pods' migration to other nodes, before killing them. It is possible to modify the time to kill using the `grace_period` parameter in the **procedure.yaml** as follows (time in seconds):

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
# Additional procedures

The following kubemarine procedures are available additionally: 
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

# Common Practice

You should not run any containers on worker nodes that are not managed by `kubelet` so as not to break the `kube-scheduler` precision.
