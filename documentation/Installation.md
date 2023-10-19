This section provides information about the inventory, features, and steps for installing a Kubernetes solution on the environment.

- [Prerequisites](#prerequisites)
  - [Prerequisites for Deployment Node](#prerequisites-for-deployment-node)
  - [Prerequisites for Cluster Nodes](#prerequisites-for-cluster-nodes)
    - [Minimal Hardware Requirements](#minimal-hardware-requirements)
    - [Recommended Hardware Requirements](#recommended-hardware-requirements)
    - [Disk Partitioning Recommendation](#disk-partitioning-recommendation)
    - [ETCD Recommendation](#etcd-recommendation)
    - [SSH key Recommendation](#ssh-key-recommendation)
    - [Private Certificate Authority](#private-certificate-authority)
- [Inventory Preparation](#inventory-preparation)
  - [Deployment Schemes](#deployment-schemes)
    - [Non-HA Deployment Schemes](#non-ha-deployment-schemes)
      - [All-in-one Scheme](#all-in-one-scheme)
    - [HA Deployment Schemes](#ha-deployment-schemes)
      - [Mini-HA Scheme](#mini-ha-scheme)
      - [Full-HA Scheme](#full-ha-scheme)
  - [Taints and Toleration](#taints-and-toleration)
  - [Configuration](#configuration)
    - [globals](#globals)
    - [node_defaults](#node_defaults)
    - [nodes](#nodes)
    - [cluster_name](#cluster_name)
    - [control_plain](#control_plain)
    - [public_cluster_ip](#public_cluster_ip)
    - [registry](#registry)
    - [gateway_nodes](#gateway_nodes)
    - [vrrp_ips](#vrrp_ips)
    - [services](#services)
      - [kubeadm](#kubeadm)
        - [Kubernetes version](#kubernetes-version)
        - [Cloud Provider Plugin](#cloud-provider-plugin)
        - [Service Account Issuer](#service-account-issuer)
      - [kubeadm_kubelet](#kubeadm_kubelet)
      - [kubeadm_patches](#kubeadm_patches)
      - [kernel_security](#kernel_security)
        - [selinux](#selinux)
        - [apparmor](#apparmor)
      - [packages](#packages)
        - [package_manager](#package_manager)
        - [management](#management)
        - [associations](#associations)
      - [thirdparties](#thirdparties)
      - [CRI](#cri)
      - [modprobe](#modprobe)
      - [sysctl](#sysctl)
      - [audit](#audit)
        - [Kubernetes Policy](#audit-kubernetes-policy)
        - [Daemon](#audit-daemon)
      - [ntp](#ntp)
        - [chrony](#chrony)
        - [timesyncd](#timesyncd)
      - [resolv.conf](#resolvconf)
      - [etc_hosts](#etc_hosts)
      - [coredns](#coredns)
      - [loadbalancer](#loadbalancer)
    - [RBAC Admission](#rbac-admission)
    - [Admission psp](#admission-psp)
      - [Configuring Admission Controller](#configuring-admission-controller)
      - [Configuring OOB Policies](#configuring-oob-policies)
      - [Configuring Custom Policies](#configuring-custom-policies)
    - [Admission pss](#admission-pss)
      - [Configuring Default Profiles](#configuring-default-profiles)
      - [Configuring Exemptions](#configuring-exemptions)
    - [RBAC Accounts](#rbac-accounts)
      - [RBAC account_defaults](#rbac-account_defaults)
    - [Plugins](#plugins)
      - [Predefined Plugins](#predefined-plugins)
        - [calico](#calico)
        - [nginx-ingress-controller](#nginx-ingress-controller)
        - [kubernetes-dashboard](#kubernetes-dashboard)
        - [local-path-provisioner](#local-path-provisioner)
      - [Plugins Features](#plugins-features)
        - [plugin_defaults](#plugin_defaults)
        - [Plugins Reinstallation](#plugins-reinstallation)
        - [Plugins Installation Order](#plugins-installation-order)
        - [Node Selector](#node-selector)
        - [Tolerations](#tolerations)
        - [Resources requets and limits](#resources-requests-and-limits)
      - [Custom Plugins Installation Procedures](#custom-plugins-installation-procedures)
        - [template](#template)
        - [config](#config) 
        - [expect pods](#expect-pods)
        - [expect deployments/daemonsets/replicasets/statefulsets](#expect-deploymentsdaemonsetsreplicasetsstatefulsets)
        - [python](#python)
        - [thirdparty](#thirdparty)
        - [shell](#shell)
        - [ansible](#ansible)
        - [helm](#helm)
  - [Advanced features](#advanced-features)
    - [List Merge Strategy](#list-merge-strategy)
      - [Merge Strategy Positioning](#merge-strategy-positioning)
      - [List Merge Allowed Sections](#list-merge-allowed-sections)
    - [Dynamic Variables](#dynamic-variables)
      - [Limitations](#limitations)
      - [Jinja2 Expressions Escaping](#jinja2-expressions-escaping)
    - [Environment Variables](#environment-variables)
  - [Installation without Internet Resources](#installation-without-internet-resources)
- [Installation Procedure](#installation-procedure)
  - [Installation Tasks Description](#installation-tasks-description)
  - [Installation of Kubernetes using CLI](#installation-of-kubernetes-using-cli)
    - [Custom Inventory File Location](#custom-inventory-file-location)
- [Installation Features](#installation-features)
  - [Tasks List Redefinition](#tasks-list-redefinition)
  - [Logging](#logging)
  - [Dump Files](#dump-files)
  - [Configurations Backup](#configurations-backup)
  - [Ansible Inventory](#ansible-inventory)
    - [Contents](#contents)
      - [[all]](#all)
      - [[cluster:children]](#clusterchildren)
      - [[balancer], [control-plane], [worker]](#balancer-control-plane-worker)
      - [[cluster:vars]](#clustervars)
  - [Cumulative Points](#cumulative-points)
- [Supported Versions](#supported-versions)

# Prerequisites

The technical requirements for all types of host VMs for Kubemarine installation are specified in this section.

## Prerequisites for Deployment Node

Ensure the following requirements are met:

**Minimal Hardware**
* 1 CPU
* 512MB RAM

**Operating System**
* Linux
* MacOS
* Windows (See [Restrictions](#windows-deployer-restrictions))

**Preinstalled Software**
* python 3.9 (or higher version)
* pip3
* Helm 3 (optional, only if Helm plugins required to be installed)

For more information about the different types of Kubemarine installation, refer to [README](../README.md).

**System Clock**

System clock should be synchronized the same way as for Cluster nodes system clock.  

### Windows Deployer Restrictions

There are the following restrictions when deploying from Windows:
* [ansible](#ansible) plugin procedures are not supported.
* All Kubemarine input text files must be in utf-8 encoding.

## Prerequisites for Cluster Nodes

For cluster machines, ensure the following requirements are met:

**Host type**
* VM
* Bare-Metal

**Host arch**
* x86-64

**Operating System**

* The following distributives and versions are supported:

  * Centos 7.5+, 8.4
  * RHEL 7.5+, 8.4, 8.6, 8.7
  * Oracle Linux 7.5+, 8.4
  * RockyLinux 8.6, 8.7
  * Ubuntu 20.04
  * Ubuntu 22.04.1

<!-- #GFCFilterMarkerStart# -->
The actual information about the supported versions can be found in `compatibility_map.distributives` section of [globals.yaml configuration](../kubemarine/resources/configurations/globals.yaml#L256).
<!-- #GFCFilterMarkerEnd# -->

**Networking**

* Opened TCP-ports:
  * Internal communication:
    * 22 : SSH 
    * 80 (or 20080, if balancers are presented): HTTP
    * 179 : Calico BGP
    * 443 (or 20443, if balancers are presented): HTTPS
    * 5473 : Calico netowrking with Typha enabled
    * 6443 : Kubernetes API server
    * 8443 : Kubernetes dashboard
    * 2379-2380 : ETCD server & client API
    * 9091 - Calico metric port
    * 9093 - Calico Typha metric port
    * 9094 - Calico kube-controller metric port
    * 10250 : Kubelet API
    * 10257 : Kube-scheduler
    * 10259 : Kube-controller-manager 
    * 10254 : Prometheus port
    * 30000-32767 : NodePort Services
  * External communication:
    * 80
    * 443
* Internal network bandwidth not less than 1GBi/s.
* Dedicated internal address, IPv4, and IPv6 are supported as well, for each VM.
* Any network security policies are disabled or whitelisted. This is especially important for OpenStack environments.
  * Traffic is allowed for pod subnet. Search for address at`services.kubeadm.networking.podSubnet`. By default, `10.128.0.0/14` for IPv4 or `fd02::/48` for IPv6.
  * Traffic is allowed for service subnet. Search for address at `services.kubeadm.networking.serviceSubnet`. By default `172.30.0.0/16` for IPv4 or `fd03::/112` for IPv6).
  * Traffic to/from podSubnet, serviceSubnet is allowed inside the cluster.

**Warning**: `Kubemarine` works only with `firewalld` as an IP firewall, and switches it off during the installation.
If you have other solution, remove or switch off the IP firewall before the installation.

**Preinstalled software**

* Installation of the following packages is highly recommended; however, Kubernetes can work without them, but may show warnings:
  * ethtool
  * ebtables
  * socat

**Warning**: You have to specify packages names in "RPM format" if it is possible for you OS,
For example, specify `conntrack-tools` instead of `conntrack`.

**Note**: For an automated installation, you can use [Packages](#packages) during installation.

**Preinstalled or RPM repository provided in `cluster.yaml` with the following RPMs from [Supported versions table](#supported-versions)**

**Note**:

* You can install a version other than the recommended version, but it is not supported and can cause unpredictable consequences.
* rh-haproxy18 (build provided by RedHat) is supported only for now.

**Warning**: RHEL 8 does not have Python preinstalled. For `check_iaas` to work correctly, it is required to install Python on the nodes. Execute the following step before the installation procedure.
* Install `python 3.9` from the standard RHEL repository:
```
# dnf install python3.9 -y
```

**Unattended-upgrades** 

`unattended-upgrades` is a native to Debian/Ubuntu automatic update mechanism. By default, it is included in the system and is configured to updating packages only from security-repository.

**Warning**: Do not use unattended-upgrade to automatically update packages besides security updates.

**Note**: Since this mechanism is launched once a day at a random time, it may coincide with the work of other package managers (apt, aptitude, dpkg, and so on), resulting in an error in these package managers. In this case, the simplest solution is to wait for the completion of the unattended-upgrades process and restart apt, aptitude, or dpkg.

**Preconfigured**
* SSHD running on each VM via port 22.
* User with sudo and no-require-tty parameter in sudoers file.
* SSH key is configured on each node. The key should be available for the connection with a username from the previous statement.

**Recommended**
* Logrotate policy for `/var/log/messages` is configured according to the planned load (it is recommended to use limited size and daily rotation)

For more information, refer to _Official Kubernetes Requirements Documentation_
at [https://kubernetes.io/docs/setup/production-environment/tools/kubeadm/install-kubeadm/#before-you-begin](https://kubernetes.io/docs/setup/production-environment/tools/kubeadm/install-kubeadm/#before-you-begin).

### Minimal Hardware Requirements

The minimum hardware requirements for cluster machines are as follows:

**Balancer**
* 1 CPU
* 1GB RAM
* 10GB HDD

**Control-plane**
* 2 CPU
* 2GB RAM
* 40GB HDD

**Worker**
* 4 CPU
* 4GB RAM
* 80GB HDD

### Recommended Hardware Requirements

The recommended hardware requirements are as follows:

**Balancer**
* 2 CPU
* 1GB RAM
* 10GB HDD

**Control-plane**
* 4 CPU
* 4GB RAM

**Worker**
* 8 CPU
* 16GB RAM
* 120GB HDD

### Disk Partitioning Recommendation

Kubernetes clusters use the following important folders:

**/var/lib/etcd** - It is used for the etcd database storage at the control-plane nodes. Etcd is very sensitive to disk performance so it is recommended to put /var/lib/etcd to a separate fast disk (for example, SSD). The size of this disk depends on the etcd database size, but not less than 4 GB. 
For more information about etcd disks, refer to the [ETCD Recommendation](#etcd-recommendation) section.

**/var/lib/containerd** - It is a working directory of containerd, and is used for active container runtimes and storage of local images. 
For control-plane nodes, it should be at least 20 GB, whereas, for worker nodes, it should be 50 GB or more, depending on the application requirements.

**/var/lib/kubelet** - It is a working directory for kubelet. It includes kubelet's configuration files, pods runtime data, environment variables, kube secrets, emptyDirs and data volumes not backed by persistent storage PVs. Its size varies depending on the running applications.

**/var/log** - It is used for logs from all Linux subsystems (logs of pods are located there too). The recommended size is 10 to 30 GB or more, depending on the logrotation policy. Also, the logrotation should be configured properly to avoid a disk overflow.

#### Disk Pressure

To detect DiskPressure events for nodes, Kubernetes controls the `nodefs` and `imagefs` file system partitions.
The `nodefs` (or `rootfs`) is the node's main filesystem used for local disk volumes, emptyDir, log storage, and so on. By default, it is /var/lib/kubelet.

The `imagefs` is an optional filesystem that the container runtimes use to store container images and container writable layers.
For containerd, it is the filesystem containing /var/lib/containerd/io.containerd.snapshotter.v1.overlayfs.

If `nodefs` or `imagefs` reach the eviction thresholds (`100% - nodefs.available`, `100% - imagefs.available`), the DiskPressure condition becomes true and the pods start being evicted from the node. So it is crucially important not to allow disk fulfillment coming to the eviction threshold for both nodefs and imagefs.

### ETCD Recommendation

For a cluster with a high load on the ETCD, it is strongly recommended to mount dedicated SSD-volumes in the ETCD-storage directory (4 GB size at least is recommended) on each Control-plane before the installation.
Mount point:

```
/var/lib/etcd
```
[General H/W recommendations](https://etcd.io/docs/latest/op-guide/hardware/)

### SSH key Recommendation 

Before working with the cluster, you need to generate an ssh key. Kubemarine supports following types of keys: *RSA, DSS, ECDSA, Ed25519*.

Example:
```
ssh-keygen -t rsa -b 4096
```

### Private Certificate Authority

In internal environments, certificates signed by the custom CA root certificate can be used, for example, in a private repository. 
In this case, the custom CA root certificate should be added to all the cluster nodes.

Examples:
* CentOS/RHEL/Oracle
```
# yum install ca-certificates
# curl -o /etc/pki/ca-trust/source/anchors/Custom_CA.crt http://example.com/misc/Custom_CA.crt
# update-ca-trust extract
```
* Ubuntu/Debian:
```
# apt install ca-certificates
# curl -o /usr/share/ca-certificates/Custom_CA.crt http://example.com/misc/Custom_CA.crt
# echo "Custom_CA.crt" >> /etc/ca-certificates.conf
# update-ca-certificates
```
# Inventory Preparation

Before you begin, select the deployment scheme and prepare the inventory.

## Deployment Schemes

Several deployment schemes exist for the cluster installation.

There are two major deployment schemes as follows:
* Non-HA Deployment
* HA Deployment 

### Non-HA Deployment Schemes

This deployment provides a single Kubemarine control-plane.

#### All-in-one Scheme

This scheme has one node assigned as control-plane and worker roles; balancer role is optional. This scheme is used for developing and demonstrating purposes only.
An example of this scheme is available in the [All-in-one Inventory Example](../examples/cluster.yaml/allinone-cluster.yaml).

The following image illustrates the All-in-one scheme.

![All-in-one Scheme](/documentation/images/all-in-one.png)

### HA Deployment Schemes

This deployment type provides a highly available and reliable solution.

#### Mini-HA Scheme

In this scheme, the control-plane, balancer, and worker roles are all assigned to odd number of identical nodes (at least 3).
In this scheme, it is mandatory to enable VRRP to leverage balancing. An example of this scheme is available in the [Mini-HA Inventory Example](../examples/cluster.yaml/miniha-cluster.yaml).

The following image illustrates the Mini-HA scheme.

![Mini-HA Scheme](/documentation/images/mini-ha.png)

#### Full-HA Scheme

In this scheme, several nodes are assigned different roles. The number of control-plane nodes should be odd, three, or more.
The number of worker nodes should be greater than one or more than three. The recommended number of balancer nodes is two, with configured VRRP, but one balancer without VRRP is also supported.
An example of this scheme presented is available in the [Minimal Full-HA Inventory Example](../examples/cluster.yaml/minimal-cluster.yaml) and [Typical Full-HA Inventory Example](../examples/cluster.yaml/typical-cluster.yaml).

The following image illustrates the Full-HA scheme.

![Full-HA Scheme](/documentation/images/full-ha.png)

## Taints and Toleration

A node, taint, lets you mark a node so that the scheduler avoids or prevents using it for certain pods. A complementary feature, tolerations, lets you designate pods that can be used on "tainted" nodes.

Node taints are key-value pairs associated with an effect. Following are the available effects:

 * NoSchedule. The pods that do not tolerate this taint are not scheduled on the node; the existing pods are not evicted from the node.
 * PreferNoSchedule. Kubernetes avoids scheduling the pods that do not tolerate this taint onto the node.
 * NoExecute. A pod is evicted from the node if it is already running on the node, and is not scheduled onto the node if it is not yet running on the node.

**Note**: Some system pods, for example, kube-proxy and fluentd, tolerate all NoExecute and NoSchedule taints, and are not evicted.

In general, taints and tolerations support the following use cases:

 * Dedicated nodes. You can use a combination of node affinity and taints/tolerations to create dedicated nodes. For example, you can limit the number of nodes onto which to schedule pods by using labels and node affinity, apply taints to these nodes, and then add corresponding tolerations to the pods to schedule them on those particular nodes.
 * Nodes with special hardware. If you have nodes with special hardware, for example, GPUs, you have to repel pods that do not need this hardware and attract pods that need it. This can be done by tainting the nodes that have the specialized hardware and adding the corresponding toleration to pods that must use this special hardware.
 * Taint-based evictions. New Kubernetes versions allow configuring per-pod eviction behavior on nodes that experience problems.

To set taint to any node, you can apply the following command:

```
kubectl taint nodes <NODENAME> <KEY>=<VALUE>:<EFFECT>
```

To remove the taint added by command above you can run:

```
kubectl taint nodes <NODENAME> <KEY>=<VALUE>:<EFFECT>-
```

Where:

 * NODENAME is the name of the tainted node.
 * KEY is the name of the taint. For example, special, database, infra, and so on.
 * VALUE is the value for the taint.
 * EFFECT is the effect for the taint behavior. It can be one of NoSchedule, PreferNoSchedule, or NoExecute.

To deploy pods on tainted nodes, you should define the toleration section:

```YAML
tolerations:
- key: <KEY>
  operator: Equal
  value: <VALUE>
  effect: <EFFECT>
```

A toleration "matches" a taint if the keys are the same and the effects are the same, and:

 * the operator is Exists (in which case no value should be specified), or
 * the operator is Equal and the values are equal.

**Note**: An empty key with operator Exists matches all keys, values, and effects which specifies that this tolerates everything.

#### CoreDNS Deployment with Node Taints

By default, CoreDNS pods are scheduled to worker nodes. If the worker nodes have taints, the CoreDNS must have tolerations configuration in cluster.yaml, otherwise, the CoreDNS pods get stuck in the Pending state. For example:
```
services:
  coredns:
    deployment:
      spec:
        template:
          spec:
             tolerations:
              - key: application
                operator: Exists
                effect: NoSchedule
```

#### Plugins Deployment with Node Taints 

The plugins also require the tolerations section in case of node taints. The Calico pods already have tolerations to be assigned to all the cluster nodes. But for other plugins, it should be set in cluster.yaml. For more information, see [Tolerations](#tolerations).

If you create your own plugins, the tolerations settings should be taken into account.

## Configuration

All the installation configurations for the cluster are in a single inventory file. It is recommended to name this file as **cluster.yaml**.

For more information about the structure of the inventory and how to specify the values, refer to the following configuration examples:
* [Minimal Full-HA Inventory Example](../examples/cluster.yaml/minimal-cluster.yaml) - It provides the minimum set of parameters required to install a cluster out of the box.
* [Typical Full-HA Inventory Example](../examples/cluster.yaml/typical-cluster.yaml) - It provides a set of parameters that you probably want to configure.
* [Full Full-HA Inventory Example](../examples/cluster.yaml/full-cluster.yaml) - It provides almost all the possible parameters that you can configure.
* [Minimal All-in-one Inventory Example](../examples/cluster.yaml/allinone-cluster.yaml) - It provides the minimum set of parameters for deploying All-in-one scheme.
* [Minimal Mini-HA Inventory Example](../examples/cluster.yaml/miniha-cluster.yaml) - It provides the minimum set of parameters for deploying Mini-HA scheme.

#### Inventory validation 

When configuring the inventory, you can use your favorite IDE supporting YAML validation by JSON schema.
JSON schema for inventory file can be used by [URL](../kubemarine/resources/schemas/cluster.json?raw=1).
Do not try to copy the schema content.

Make sure to use a raw URL (at raw.githubusercontent.com) without any query parameters.
The JSON schema is naturally versioned by a Kubemarine version, specifically, by GitHub tag or branch that you are currently checking.

Note that the inventory file is validated against the same schema at runtime.

The known IDEs that support validation are:
* [PyCharm](https://www.jetbrains.com/help/pycharm/json.html#ws_json_schema_add_custom) or other IntelliJ based IDEs.
* Red Hat's extension for [Visual Studio Code](https://marketplace.visualstudio.com/items?itemName=redhat.vscode-yaml).

The inventory file consists of the following sections.

### globals
In the `globals` section you can describe the global parameters that can be overridden. For example:

```
globals:
  expect:
    pods:
      plugins:
        retries: 300
  nodes:
    ready:
      timeout: 10
      retries: 60
    boot:
      timeout: 900
```

The following parameters are supported:

| Name                             | Type | Mandatory | Default Value | Example | Description                                                                                                        |
|----------------------------------|------|-----------|---------------|---------|--------------------------------------------------------------------------------------------------------------------|
| `expect.deployments.timeout`     | int  | no        | 5             | `10`    | Timeout between `expect.deployments.retries` for daemonsets/deployments/replicasets/statefulsets readiness waiting |
| `expect.deployments.retries`     | int  | no        | 45            | `100`   | Number of retires to check daemonsets/deployments/replicasets/statefulsets readiness                               |
| `expect.pods.kubernetes.timeout` | int  | no        | 5             | `10`    | Timeout between `expect.pods.kubernetes.retries` for control-plane pods readiness waiting                          |
| `expect.pods.kubernetes.retries` | int  | no        | 30            | `50`    | Number of retires to check control-plane pods readiness                                                            |
| `expect.pods.plugins.timeout`    | int  | no        | 5             | `10`    | Timeout between `expect.pods.plugins.retries` for pods readiness waiting in `plugins`                              |
| `expect.pods.plugins.retries`    | int  | no        | 150           | `300`   | Number of retires to check pods readiness in `plugins`                                                             |
| `nodes.ready.timeout`            | int  | no        | 5             | `10`    | Timeout between `nodes.ready.retries` for cluster node readiness waiting                                           |
| `nodes.ready.retries`            | int  | no        | 15            | `60`    | Number of retries to check a cluster node readiness                                                                |
| `nodes.boot.timeout`             | int  | no        | 600           | `900`   | Timeout for node reboot waiting                                                                                    |


### node_defaults

In the `node_defaults` section, you can describe the parameters to be applied by default to each record in the [nodes](#nodes) section.
For example, by adding the `keyfile` parameter in this section, it is copied to all elements of the nodes list.
However, if this parameter is defined in any element of nodes list, it is not replaced in it.

For example, you can have the following inventory content:

```yaml
node_defaults:
  keyfile: "/home/username/.ssh/id_rsa"
  username: "centos"

node:
  - name: "lb"
    internal_address: "192.168.0.1"
    roles: ["balancer"]
  - name: "control-plane"
    keyfile: "/home/username/another.key"
    internal_address: "192.168.0.2"
    roles: ["control-plane"]
```

After executing the above example, the final result is displayed as follows:

```yaml
node:
  - name: "lb"
    username: "centos"
    keyfile: "/home/username/.ssh/id_rsa"
    internal_address: "192.168.0.1"
    roles: ["balancer"]
  - name: "control-plane"
    username: "centos"
    keyfile: "/home/username/another.key"
    internal_address: "192.168.0.2"
    roles: ["control-plane"]
```

Following are the parameters allowed to be specified in the `node_defaults` section:
* keyfile, password, username, connection_port, connection_timeout and gateway.
* labels, and taints - specify at global level only if the [Mini-HA Scheme](#mini-ha-scheme) is used.
For more information about the listed parameters, refer to the following section.

Note: To establish an ssh connection, you can use either a keyfile or a password. In case if you are specifying both, keyfile will be considered on priority.

Note: Set an environment variable with the desired password. For example, you can use `export PASS="your_password"`. In the cluster.yaml file, specify the password field using the environment variable syntax. For instance: `password: '{{ env.PASS }}'`. This syntax instructs the code to fetch the value from the PASS environment variable and substitute it into the password field when reading the configuration file. See more details about [environment variables](#environment-variables) 
### nodes

In the `nodes` section, it is necessary to describe each node of the future cluster.

The following options are supported:

|Name|Type|Mandatory|Default Value|Example|Description|
|---|---|---|---|---|---|
|keyfile|string|no| |`/home/username/.ssh/id_rsa`|**Absolute** path to keyfile on local machine to access the cluster machines, Either a keyfile or a password should be provided|
|password|string|no| |`password@123`|Password to access the cluster machines, Either a keyfile or a password should be provided|
|username|string|no|`root`|`centos`|Username for SSH-access the cluster machines|
|name|string|no| |`k8s-control-plane-1`|Cluster member name. If omitted, Kubemarine calculates the name by the member role and position in the inventory. Note that this leads to undefined behavior when adding or removing nodes.|
|address|ip address|no| |`10.101.0.1`|External node's IP-address|
|internal_address|ip address|**yes**| |`192.168.0.1`|Internal node's IP-address|
|connection_port|int|no|`22`| |Port for SSH-connection to cluster node|
|connection_timeout|int|no|10|`60`|Timeout for SSH-connection to cluster node|
|roles|list|**yes**| |`["control-plane"]`|Cluster member role. It can be `balancer`, `worker`, or `control-plane`.|
|labels|map|no| |`netcracker-infra: infra`|Additional labels for node|
|taints|list|no| |See examples below|Additional taints for node. **Caution**: Use at your own risk. It can cause unexpected behavior. No support is provided for consequences.|

An example with parameters values is as follows:

```yaml
node_defaults:
  keyfile: "/home/username/.ssh/id_rsa"
  password: '{{ env.PASS }}'     #Either keyfile or password can be used.
  username: "centos"

nodes:
  - name: "k8s-lb"
    address: "10.101.0.1"
    internal_address: "192.168.0.1"
    roles: ["balancer"]
  - name: "k8s-control-plane-1"
    address: "10.101.0.2"
    internal_address: "192.168.0.2"
    roles: ["control-plane"]
    labels:
      region: asia
    taints:
      - "node-role.kubernetes.io/remove-example:NoSchedule-"
      - "node-role.kubernetes.io/add-example=add-example:NoSchedule"
  - name: "k8s-worker-1"
    address: "10.101.0.5"
    internal_address: "192.168.0.5"
    roles: ["worker"]
    labels:
      netcracker-infra: infra
      region: europe
```

The example is also available in [Full Inventory Example](../examples/cluster.yaml/full-cluster.yaml).

**Warning**: Please be informed that the `master` role is obsolete and will be changed by `control-plane`in the future. The 
`control-plane` and `master` roles are interchangeable at the moment. Therefore it's possible to use the `control-plane` and 
`master` roles in any procedure.

### cluster_name

In the `cluster_name` variable specify the future address of the cluster.
On this address, the Control Plane Endpoint is raised, and it is used in the calculated parameters.

An example is as follows:

```yaml
cluster_name: "k8s-stack.sdntest.example.com"
```

**Note**: Cluster name should be a fully qualified domain name. It should not be an IP address.

<!-- #GFCFilterMarkerStart# -->

For more information, refer to _FQDN_ at https://en.wikipedia.org/wiki/Fully_qualified_domain_name

<!-- #GFCFilterMarkerEnd# -->


### control_plain

`control_plain` parameter specifies which addresses are to be available for Kubernetes. The internal and external parameter is described in the following table.

| Parameter | Example | Description |
|-----------|---------|-------------|
| `control_plain['internal']` | `192.168.0.1` | Internal network address for the connection. To be used for all internal kubeapi traffic. |
| `control_plain['external']` | `10.101.0.1` | External network address for the connection. To be used for serving and balancing external traffic and external connections. |

This parameter is calculated in the first turn so that it can be referenced in inventory parameters. 
For example:

```yaml
answer: '3600 IN A {{ control_plain["internal"] }}'
```

This is an autocalculated parameter, but you can override it if you are aware about the procedure. 
For example:

```yaml
control_plain:
  internal: 192.168.0.1
  external: 10.101.0.1
```

Automatic calculation works according to the following principle: 
The algorithm iterates through and looks for appropriate addresses. 

Addresses are taken from the following groups in order:

1. VRRP IP
1. Balancer
1. Control-plane

**Note**: VRRP IPs with `maintenance-type: "not bind"` do not participate in the control_plain calculation.
For more information, see [maintenance type](#maintenance-type).

**Note**: It is important to notice that addresses may not necessarily be taken from a single group. There may be situation that the internal address is taken from the VRRP, and the external one from the Balancer. This situation is not recommended, but it is possible. If the inventory is correctly filled in and all the addresses that are available are indicated, the algorithm automatically selects the best pair of addresses.

After detecting addresses, the algorithm automatically displays the determined addresses and their sources as follows:

```yaml
Control plains:
   Internal: 192.168.0.1 (vrrp_ip[0])
   External: 10.101.1.101 (balancer "balancer-1")
```

#### control_endpoint

The algorithm of [control_plain](#control_plain) calculation chooses the very first address if there are several elements in the group.
If you are not satisfied with this principle, you can "help" the algorithm in choosing which address to take by specifying the `control_endpoint` parameter for the group element.
For example:

```yaml
vrrp_ips:
- ip: 192.168.0.1
  floating_ip: 10.101.0.1
- ip: 192.168.0.2
  floating_ip: 10.101.0.2
  control_endpoint: True
```

The above example produces the following result:

```
Control plains:
   Internal: 192.168.0.2 (vrrp_ip[1])
   External: 10.101.0.2 (vrrp_ip[1])
```

An example with mixed groups:

```yaml
vrrp_ips:
- ip: 192.168.0.1
  floating_ip: 10.101.0.1
- ip: 192.168.0.2
  control_endpoint: True

nodes:
- name: balancer-1
  internal_address: 192.168.0.3
  address: 10.101.0.3
- name: balancer-2
  internal_address: 192.168.0.4
  address: 10.101.0.4
  control_endpoint: True
```

The above example produces the following result:

```
Control plains:
   Internal: 192.168.0.2 (vrrp_ip[1])
   External: 10.101.0.4 (balancer "balancer-2")
```

**Note**: `control_endpoint` is not taken into account for VRRP IPs with `maintenance-type: "not bind"`.

### public_cluster_ip

**Warning**: `public_cluster_ip` is an obsolete variable, use `control_plain.external` variable instead.

`public_cluster_ip` variable specifies the Kubernetes external address to connect from an external network.
This variable is optional and required if you are using Helm plugins installation.

By default `public_cluster_ip` inherits `control_plain["external"]` as shown in the following code:

```yaml
public_cluster_ip: '{{ control_plain["external"] }}'
```

However, it is possible to change an address if the external control_plain parameter is not suitable. For example, if the cluster is behind an external balancer as shown in the following code.

```yaml
public_cluster_ip: "10.102.0.1"
```

### registry

If you want to install Kubernetes in a private environment, without access to the internet, then you
need to redefine the addresses of remote resources. These resources are many, so for convenience 
there is a single unified registry parameter that allows you to specify the registry for everything 
at once. To do this, you need to specify `registry` section in the root of the inventory and fill it
with parameters. 

The `registry` parameter automatically completes the following parameters:

| Path                                                         |Registry Type| Format                                                                                                         |Example|Description|
|--------------------------------------------------------------|---|----------------------------------------------------------------------------------------------------------------|---|---|
| `services.kubeadm.imageRepository`                           |Docker| Address without protocol, where Kubernetes images are stored. It should be the full path to the repository.    |```example.com:5443/registry.k8s.io```|Kubernetes Image Repository. The system container's images such as `kubeapi` or `etcd` is loaded from this registry.|
| `services.cri.dockerConfig.insecure-registries`              |Docker| List with addresses without a protocol.                                                                        |```example.com:5443```|Docker Insecure Registries. It is necessary for the Docker to allow the connection to addresses unknown to it.|
| `services.cri.dockerConfig.registry-mirrors`                 |Docker| List with addresses. Each address should contain a protocol.                                                   |```https://example.com:5443```|Docker Registry Mirrors. Additional image sources for the container's images pull.|
| `services.cri.containerdConfig.{{containerd-specific name}}` |Docker| Toml-like section with endpoints according to the containerd docs.                                             |```https://example.com:5443```||
| `services.cri.containerdRegistriesConfig.{{registry}}`       |Docker| Toml-like section with hosts.toml content for specific registry according to the containerd docs. |```https://example.com:5443```||
| `services.thirdparties.{{ thirdparty }}.source`              |Plain| Address with protocol or absolute path on deploy node. It should be the full path to the file.                 |```https://example.com/kubeadm/v1.22.2/bin/linux/amd64/kubeadm```|Thridparty Source. Thirdparty file, such as binary, archive and so on, is loaded from this registry.|
| `plugin_defaults.installation.registry`                      |Docker| Address without protocol, where plugins images are stored.                                                     |```example.com:5443```|Plugins Images Registry. All plugins container's images are loaded from this registry.|

**Note**: You can enter these parameters yourself, as well as override them, even if the `registry` parameter is set.

Registry section support 2 formats - new endpoints definition without docker support and old-style
address-port with docker support. We recommend to use new endpoints format as in the future we will 
abandon the old format. Only one format can be used.


#### registry (new endpoints format)

The following parameters are supported:

| Parameter       | Type   | Default value            | Description                                                                                   |
|-----------------|--------|--------------------------|-----------------------------------------------------------------------------------------------|
| endpoints       | list   |                          | Address list of registry endpoints                                                           |
| mirror_registry | string | `registry.cluster.local` | The internal address of the containerd mirror registry, which should be defined in containers |
| thirdparties    | string |                          | Address for the webserver, where thirdparties hosted                                          |

Endpoint value is a string with an address (protocol, host, and port). Record format example:

```yaml
registry:
  endpoints:
    - https://repository-01.example.com:17001
    - https://repository-02.example.com:27001
```

Also, you can mix this types. Full example:

```yaml
registry:
  thirdparties: https://repository-03.example.com:8080/custom_location
  endpoints:
    - https://repository-01.example.com:17001
    - https://repository-02.example.com:27001
  mirror_registry: "registry.cluster.local"
```


#### registry (old address-port format)

The following parameters are supported:

| Parameter   | Type    | Default value | Description                                                  |
|-------------|---------|---------------|--------------------------------------------------------------|
| address     | string  |               | Full address to the registry, without protocol and port.     |
| docker_port | number  |               | Custom port for connecting to the image registry.               |
| webserver   | boolean | `False`       | A special parameter indicating whether registry has ability to serve http files. When enabled, the `thirdparties` are patched with the `address` provided. | 
| ssl         | boolean | `False`       | Registry SSL support switch.                                 |

Example:

```yaml
registry:
  address: example.com
  docker_port: 5443
  webserver: True
  ssl: False
```

This configuration generates the following parameters:

```yaml
services:
  kubeadm:
    imageRepository: example.com:5443/registry.k8s.io
  cri:
    dockerConfig:
      insecure-registries:
      - example.com:5443
      registry-mirrors:
      - http://example.com:5443
  thirdparties:
    /usr/bin/calicoctl:
      source: http://example.com/webserver/repository/raw/projectcalico/calico/v3.20.1/calicoctl-linux-amd64
    /usr/bin/kubeadm:
      source: http://example.com/webserver/repository/raw/kubernetes/kubeadm/v1.22.2/bin/linux/amd64/kubeadm
    /usr/bin/kubectl:
      source: http://example.com/webserver/repository/raw/kubernetes/kubectl/v1.22.2/bin/linux/amd64/kubectl
    /usr/bin/kubelet:
      source: http://example.com/webserver/repository/raw/kubernetes/kubelet/v1.22.2/bin/linux/amd64/kubelet
plugin_defaults:
  installation:
    registry: example.com:5443
```

However, if you override one of the replaced parameters, it is not replaced. For example, with the following configuration:

```yaml
registry:
  address: example.com
  docker_port: 5443
  webserver: True
  ssl: False
services:
  kubeadm:
    imageRepository: 1.1.1.1:8080/test
```

The following configuration is produced:

```yaml
services:
  kubeadm:
    imageRepository: 1.1.1.1:8080/test
  cri:
    dockerConfig:
      insecure-registries:
      - example.com:5443
      registry-mirrors:
      - http://example.com:5443
...
```

### gateway_nodes

If you do not have direct SSH-access to the cluster nodes from the deployer node and you need to connect via the gateway, you can specify the gateway nodes through which you need to create an SSH-tunnel.
You can specify several gateways.

The following parameters are supported:

|Parameter|Type|Mandatory|Description|
|---|---|---|---|
|**name**|string|**yes**|Gateway node name|
|**address**|ip address|**yes**|Gateway node's IP or hostname address for connection|
|**username**|string|**yes**|Username for SSH-access the gateway node|
|**keyfile**|string|no|**Absolute** path to keyfile on local machine to access the cluster machines, Either a keyfile or a password should be provided|
|**password**|string|no|Password to access the cluster machines, Either a keyfile or a password should be provided|

An example is as follows:

```yaml
gateway_nodes:
  - name: k8s-gateway-1
    address: 10.102.0.1
    username: root
    password: '{{ env.PASS }}'
    keyfile: "/home/username/.ssh/id_rsa"
    
  - name: k8s-gateway-2
    address: 10.102.0.2
    username: root
    password: '{{ env.PASS }}'
    keyfile: "/home/username/.ssh/id_rsa"
```

You need to specify which gateways should be used to connect to nodes.

An example is as follows:

```yaml
nodes:
  - name: "k8s-control-plane-1"
    address: "10.101.0.2"
    internal_address: "192.168.0.2"
    roles: ["control-plane"]
    gateway: k8s-gateway-1
  - name: "k8s-control-plane-2"
    address: "10.101.0.3"
    internal_address: "192.168.0.3"
    roles: ["control-plane"]
    gateway: k8s-gateway-2
```

**Note**: If the gateway is not specified on the node, then the connection is direct.

**Note**: To establish an ssh connection, you can use either a keyfile or a password.
### vrrp_ips

*Installation task*: `deploy.loadbalancer.keepalived`

*Can cause reboot*: No

*Can restart service*: Always yes, `keepalived`

*OS specific*: Yes, different OS may have different default network interfaces.
For interfaces with the autodetection mode selected, it is automatically detected by the `internal_address` property of the node on which the particular VRRP IP should be set.
By default, autodetection is enabled.

In order to assign VRRP IP you need to create a `vrrp_ips` section in the inventory and specify the appropriate configuration.
You can specify several VRRP IP addresses.

The following parameters are supported:

|Parameter|Default or Automatically Calculated Value|Description|
|---|---|---|
|hosts| | List of hosts on which the VRRP IP should be set.|
|hosts[i].name| |The name of the node. It must match the name in the `nodes` list.|
|hosts[i].priority|`255 - {{ i }}`|The priority of the VRRP IP host.|
|hosts[i].interface|`auto`|The interface on which the address must be listened for the particular host.|
|ip| |The IP address for virtual IP.|
|floating_ip| |The floating IP address for virtual IP.|
|interface|`auto`|The interface on which the address must be listened. The value of this property is propagated to the corresponding `hosts[i].interface` property, if the latter is not explicitly defined.|
|id|`md5({{ interface }} + {{ ip }})` cropped to 10 characters|The ID of the VRRP IP. It must be unique for each VRRP IP.|
|password|Randomly generated 8-digit string|Password for VRRP IP set. It must be unique for every VRRP IP ID.|
|router_id|Last octet of IP|The router ID of the VRRP IP. Must be unique for each VRRP IP ID and have maximum 3-character size.|
|params.maintenance-type| |Label for IPs that describes what type of traffic should be received in `maintenance` mode. See [maintenance mode](#maintenance-mode) and [maintenance type](#maintenance-type)|

There are several formats in which you can specify values.

The following are some examples of the format:

You can specify only the address of the VRRP IP, in which case it automatically applies to all balancers in the cluster and other parameters are automatically calculated.
For example:

```yaml
vrrp_ips:
- 192.168.0.1
```

You can specify the address and which hosts it should apply to. Other parameters are automatically calculated.
For example:

```yaml
vrrp_ips:
- hosts:
  - name: balancer-1
    priority: 254
  - name: balancer-2
    priority: 253
  ip: 192.168.0.1
  floating_ip: 10.101.1.1
```

You can specify all possible parameters at one time instead of using auto-calculated. For example:

```yaml
vrrp_ips:
- hosts:
  - name: balancer-1
    priority: 254
    interface: eth0
  - name: balancer-2
    priority: 253
    interface: ens3
  id: d8efc729e4
  ip: 192.168.0.1
  floating_ip: 10.101.1.1
  password: 11a1aabe
  router_id: '1'
```

#### maintenance type

Generally, the maintenance configuration is the same as the default configuration for balancer. The `maintenance_type` option allows to change the default behavior.
The following example discribes the type of traffic that applicable for particular IP in maintenance mode configuration. (`not bind` means that IP will not receive neither TCP nor HTTP traffic):

```yaml
vrrp_ips:
- ip: 192.168.0.1
  floating_ip: 10.101.1.1
- ip: 192.168.0.2
  floating_ip: 10.101.1.2
  params:
    maintenance-type: "not bind"
```

### Services

In the `services` section, you can configure the service settings. The settings are described in the following sections.

#### kubeadm

*Installation task*: `deploy.kubernetes`

*Can cause reboot*: no

*Can restart service*: always yes, `kubelet`

*OS specific*: No

In `services.kubeadm` section, you can override the original settings for the kubeadm. For more information these settings, refer to the [Official Kubernetes Documentation](https://kubernetes.io/docs/reference/setup-tools/kubeadm/kubeadm-init/#config-file).
By default, the installer uses the following parameters:

|Parameter| Default Value                                            |
|---|----------------------------------------------------------|
|kubernetesVersion| `v1.26.7`                                                |
|controlPlaneEndpoint| `{{ cluster_name }}:6443`                                |
|networking.podSubnet| `10.128.0.0/14` for IPv4 or `fd02::/48` for IPv6         |
|networking.serviceSubnet| `172.30.0.0/16` for IPv4 or `fd03::/112` for IPv6        |
|apiServer.certSANs| List with all nodes internal IPs, external IPs and names |
|apiServer.extraArgs.enable-admission-plugins| `NodeRestriction`                                        |
|apiServer.extraArgs.profiling| `false`                                                  |
|apiServer.extraArgs.audit-log-path| `/var/log/kubernetes/audit/audit.log`                    |
|apiServer.extraArgs.audit-policy-file| `/etc/kubernetes/audit-policy.yaml`                      |
|apiServer.extraArgs.audit-log-maxage| `30`                                                     |
|apiServer.extraArgs.audit-log-maxbackup| `10`                                                     |
|apiServer.extraArgs.audit-log-maxsize| `100`                                                    |
|scheduler.extraArgs.profiling| `false`                                                  |
|controllerManager.extraArgs.profiling| `false`                                                  |
|controllerManager.extraArgs.terminated-pod-gc-threshold| `1000`                                                   |

The following is an example of kubeadm defaults override:

```yaml
services:
  kubeadm:
    networking:
      podSubnet: '10.128.0.0/14'
      serviceSubnet: '172.30.0.0/16'
    imageRepository: example.com:5443/registry.k8s.io
    apiServer:
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

```

**Note**: Those parameters remain in manifests files after Kubernetes upgrade. That is the proper way to preserve custom settings for system services.

**Warning**: These kubeadm parameters are configurable only during installation, currently. 
Kubemarine currently do not provide special procedure to change these parameters after installation.

During init, join, upgrade procedures kubeadm runs `preflight` procedure to do some preliminary checks. In case of any error kubeadm stops working. Sometimes it is necessary to ignore some preflight errors to deploy or upgrade successfully.

Kubemarine allows to configure kubeadm preflight errors to be ignored.

Example:

```yaml
services:
  kubeadm_flags:
    ignorePreflightErrors: Port-6443,CoreDNSUnsupportedPlugins,DirAvailable--var-lib-etcd
```

**Note**: Default settings for `ignorePreflightErrors` are:

```yaml
services:
  kubeadm_flags:
    ignorePreflightErrors: Port-6443,CoreDNSUnsupportedPlugins
```


#### Kubernetes version

By default, the `1.26.7` version of the Kubernetes is installed. See the table of supported versions for details in [Supported versions section](#supported-versions). However, we recommend that you explicitly specify the version you are about to install. This version applies into all the dependent parameters - images, binaries, rpms, configurations: all these are downloaded and used according to your choice. To specify the version, use the following parameter as in example:

```yaml
services:
  kubeadm:
    kubernetesVersion: v1.26.7
```

#### Cloud Provider Plugin

Before proceeding further, it is recommended to read the official Kubernetes Guide about the CPP deployment in the cluster at [https://kubernetes.io/blog/2020/02/07/deploying-external-openstack-cloud-provider-with-kubeadm/](https://kubernetes.io/blog/2020/02/07/deploying-external-openstack-cloud-provider-with-kubeadm/).

**Warning**: Manual CPP installation on a deployed cluster can cause Kubernetes out-of-service denial and break Kubemarine procedures for adding and removing nodes.

It is possible to specify a plugin at the installation stage, if it is required. To enable the CPP support, just specify the `external-cloud-volume-plugin` parameter of `controllerManager` in the `kubeadm` cluster configuration. For example:

```yaml
services:
  kubeadm:
    controllerManager:
      extraArgs:
        external-cloud-volume-plugin: openstack
      extraVolumes:
      - name: "cloud-config"
        hostPath: "/etc/kubernetes/cloud-config"
        mountPath: "/etc/kubernetes/cloud-config"
        readOnly: true
        pathType: File
```

In this case, Kubemarine automatically initializes and joins new cluster nodes with CPP enabled. However, this is not enough for the full operation of the CPP. There are a number of manual steps required to configure the CPP before running Calico and other plugins. These steps depend directly on your Cloud Provider and its specific settings. An example of a simple setup for an openstack is as follows:

1. Prepare cloud config of your Cloud Provider with credentials and mandatory parameters required for the connection. Openstack cloud config example:

   ```ini
   [Global]
   region=RegionOne
   username=username
   password=password
   auth-url=https://openstack.cloud:5000/v3
   tenant-id=14ba698c0aec4fd6b7dc8c310f664009
   domain-name=default
   ```

1. Upload the cloud config to all the nodes in the cluster to the following location:

   ```
   /etc/kubernetes/cloud-config
   ```

   It is recommended to use Kubemarine functionality of plugins or thirdparties for automatic uploading. For example, it is possible to upload the cloud config on all nodes using thirdparties before starting the cluster installation:

   ```yaml
   services:
     thirdparties:
       /etc/kubernetes/cloud-config:
         source: ./example/cloud-config.txt
   ```

1. Before running any plugins, it is necessary to create a secret RBAC resource and cloud controller manager DaemonSet for CPP. This can be specified as the very first Kubemarine plugin, for example:

   Create a file `./openstack-cloud-controller-manager-ds.yaml` on deploy node with the following content:

  ```shell
  ---
    apiVersion: v1
    kind: ServiceAccount
    metadata:
      name: cloud-controller-manager
      namespace: kube-system
  ---
    apiVersion: apps/v1
    kind: DaemonSet
    metadata:
      name: openstack-cloud-controller-manager
      namespace: kube-system
      labels:
        k8s-app: openstack-cloud-controller-manager
    spec:
      selector:
        matchLabels:
          k8s-app: openstack-cloud-controller-manager
      updateStrategy:
        type: RollingUpdate
      template:
        metadata:
          labels:
            k8s-app: openstack-cloud-controller-manager
        spec:
          nodeSelector:
            node-role.kubernetes.io/control-plane: ""
          tolerations:
          - key: node.cloudprovider.kubernetes.io/uninitialized
            value: "true"
            effect: NoSchedule
          - key: node-role.kubernetes.io/control-plane
            effect: NoSchedule
          - effect: NoSchedule
            key: node.kubernetes.io/not-ready
          serviceAccountName: cloud-controller-manager
          containers:
            - name: openstack-cloud-controller-manager
              image: docker.io/k8scloudprovider/openstack-cloud-controller-manager:v1.15.0
              securityContext:
                privileged: true
              args:
                - /bin/openstack-cloud-controller-manager
                - --v=1
                - --cloud-config=$(CLOUD_CONFIG)
                - --cloud-provider=openstack
                - --use-service-account-credentials=true
                - --address=127.0.0.1
              volumeMounts:
                - mountPath: /etc/kubernetes/pki
                  name: k8s-certs
                  readOnly: true
                - mountPath: /etc/config
                  name: cloud-config-volume
                  readOnly: true
                - mountPath: /usr/libexec/kubernetes/kubelet-plugins/volume/exec
                  name: flexvolume-dir
              resources:
                requests:
                  cpu: 200m
              env:
                - name: CLOUD_CONFIG
                  value: /etc/config/cloud.conf
          hostNetwork: true
          volumes:
          - hostPath:
              path: /usr/libexec/kubernetes/kubelet-plugins/volume/exec
              type: DirectoryOrCreate
            name: flexvolume-dir
          - hostPath:
              path: /etc/kubernetes/pki
              type: DirectoryOrCreate
            name: k8s-certs
          - name: cloud-config-volume
            secret:
              secretName: cloud-config
          - name: ca-cert
            secret:
              secretName: openstack-ca-cert
  ```
   **Warning:** Pay attention on external resources links. 
   For restricted environments links should be changed to local registry.
   For example, image: `docker.io/k8scloudprovider/openstack-cloud-controller-manager:v1.15.0` should be changed to
   `registry:17001/k8scloudprovider/openstack-cloud-controller-manager:v1.15.0`
  
  **Warning**: Pay attention to pod security policies for cloud controller manager. You can create new ClusterRole or disable PSP.

   Place the following plugin section to the cluster config:
   
   ```yaml
   plugins:
     cloud-config:
       install: true
       installation:
         priority: -1
         procedures:
           - shell:
             command: sudo kubectl create secret -n kube-system generic cloud-config --from-literal=cloud.conf="$(sudo cat /etc/kubernetes/cloud-config)" --dry-run -o yaml > cloud-config-secret.yaml && sudo kubectl apply -f cloud-config-secret.yaml
             nodes: ['control-plane-1']
           - shell:
             command: sudo kubectl apply -f https://github.com/kubernetes/cloud-provider-openstack/raw/release-1.15/cluster/addons/rbac/cloud-controller-manager-roles.yaml
             nodes: ['control-plane-1']
           - shell:
             command: sudo kubectl apply -f https://github.com/kubernetes/cloud-provider-openstack/raw/release-1.15/cluster/addons/rbac/cloud-controller-manager-role-bindings.yaml
             nodes: ['control-plane-1']
           - template:
             source: ./openstack-cloud-controller-manager-ds.yaml
   ```
   **Warning**: Pay attention on external resources links.
   For restricted environments configs should be downloaded and links changed to the local path.

### Service Account Issuer

**Warning**: 

* Manual Service Account Issuer setup on an already installed Kubernetes cluster is not supported.
* Service Account Issuer feature is supported only on Kubernetes 1.20.

If Service Account Issuer is required, you can configure the necessary Kubernetes parameters using the `kubeadm` section in the cluster config. For example:

```yaml
services:
  kubeadm:
    apiServer:
      extraArgs:
        feature-gates: "ServiceAccountIssuerDiscovery=true"
        service-account-issuer: "https://{{ cluster_name }}:6443"
        service-account-jwks-uri: "https://{{ cluster_name }}:6443/openid/v1/jwks"
        service-account-signing-key-file: /etc/kubernetes/pki/sa.key
        service-account-key-file: /etc/kubernetes/pki/sa.pub
    controllerManager:
      extraArgs:
        feature-gates: "ServiceAccountIssuerDiscovery=true"
    scheduler:
      extraArgs:
        feature-gates: "ServiceAccountIssuerDiscovery=true"
```

To be able to fetch the public keys and validate the JWT tokens against the Kubernetes cluster’s issuer, you have to allow external unauthenticated requests.
To do this, bind the special role, system:service-account-issuer-discovery, with a ClusterRoleBinding to unauthenticated users. Make sure that this is safe in your environment, but only public keys are visible on the URL.

**Warning**: The following command opens an unauthenticated access to the endpoint receiving public tokens. Do not execute this command if you do not need to open access to the outside, or if you do not understand what you are doing. If you still decide to open an external access, make sure to provide secure access to this endpoint with external resources outside the cluster.

For example:

```bash
kubectl create clusterrolebinding oidc-reviewer --clusterrole=system:service-account-issuer-discovery --group=system:unauthenticated
```

If you need to test that the Service Account Issuer is working, implement the following steps:

1. Create a test pod:
```shell
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: nginx
spec:
  serviceAccountName: default
  containers:
    - image: nginx:alpine
      name: oidc
      volumeMounts:
        - mountPath: /var/run/secrets/tokens
          name: oidc-token
  volumes:
    - name: oidc-token
      projected:
        sources:
          - serviceAccountToken:
              path: oidc-token
              expirationSeconds: 7200
              audience: vault
EOF
```

2. Verify whether oidc-token is available:

```bash
kubectl exec nginx -- cat /var/run/secrets/tokens/oidc-token
```

3. Verify ServiceAccount JWT:

```bash
kubectl exec nginx -- cat /var/run/secrets/kubernetes.io/serviceaccount/token
```

4. Get the CA signing certificate of the Kubernetes API Server’s certificate to validate it:

```bash
kubectl exec nginx -- cat /var/run/secrets/kubernetes.io/serviceaccount/ca.crt > kubernetes_ca.crt
```

5. Visit well-known OIDC URLs:

```bash
curl --cacert kubernetes_ca.crt https://CLUSTER_NAME:6443/.well-known/openid-configuration
```

Example result:

```json
{
  "issuer": "https://localhost:6443",
  "jwks_uri": "https://localhost:6443/openid/v1/jwks",
  "response_types_supported": [
    "id_token"
  ],
  "subject_types_supported": [
    "public"
  ],
  "id_token_signing_alg_values_supported": [
    "RS256"
  ]
}
```

6. Visit the JWKS address ("jwks_uri") to view public keys:

```bash
curl --cacert kubernetes_ca.crt https://CLUSTER_NAME:6443/openid/v1/jwks
```

Example result:

```json
{
  "keys": [
    {
      "use": "sig",
      "kty": "RSA",
      "kid": "Rt3TBA31bh3rH67PQbKImg2ldwhPqBTWF2w1Hxqi84c",
      "alg": "RS256",
      "n": "vL0tjBqLDFTyqOCPBQC5Mww_3xkhlkWmeklPjSAhFuqL0U-Oie9E1z8FuhcApBaUs7UEPzja02PEZd4i1UF2UDoxKYEG9hG5vPseTXwN_xGnbhOaBdfgQ7KDvqV-WHfmlrnnCizi1VmNAHsoAg6oZMiUdOuk8kCFxpe0N6THmBKNSKnqoRnhSL4uwHSBWJ5pEyWAqyL8KYaaGYhc2MVUs3I8e-gtQE6Vlwe75_QSp9uIZNZeFr5keqiXhz8BWL76ok-vY8UZ8-rH2VIN5LzXkCvhIFI9W_UBzziSnb9l5dgSQCwGf18zVgT0yJjCz0Z9YE9A1Wgeu-LLrJz3gxR8Hw",
      "e": "AQAB"
    }
  ]
}
```

#### kubeadm_kubelet

*Installation task*: `deploy.kubernetes`

*Can cause reboot*: no

*Can restart service*: always yes, `kubelet`

*OS specific*: No

In `services.kubeadm_kubelet` section, you can override the original settings for the kubelet. For more information these settings, refer to the [Official Kubernetes Documentation](https://kubernetes.io/docs/reference/setup-tools/kubeadm/kubeadm-init/#config-file).
By default, the installer uses the following parameters:

|Parameter|Default Value|
|---|---|
|readOnlyPort|0|
|protectKernelDefaults|true|
|podPidsLimit|4096|
|maxPods|110|
|cgroupDriver|systemd|
|serializeImagePulls|false|

`podPidsLimit` the default value is chosen to prevent [Fork Bomb](https://en.wikipedia.org/wiki/Fork_bomb)

`cgroupDriver` field defines which cgroup driver the kubelet controls. [Configuring the kubelet cgroup driver](https://kubernetes.io/docs/tasks/administer-cluster/kubeadm/configure-cgroup-driver/#configuring-the-kubelet-cgroup-driver).

`serializeImagePulls` parameter defines whether the images will be pulled in parallel (false) or one at a time.

**Warning**: If you want to change the values of variables `podPidsLimit` and `maxPods`, you have to update the value of the `pid_max` (this value should not less than result of next expression: `maxPods * podPidsLimit + 2048`), which can be done using task `prepare.system.sysctl`. To get more info about `pid_max` you can go to [sysctl](#sysctl) section.

The following is an example of kubeadm defaults override:

```yaml
services:
  kubeadm_kubelet:
    readOnlyPort: 0
    protectKernelDefaults: true
    podPidsLimit: 2048
    maxPods: 100
    cgroupDriver: systemd
```

#### kubeadm_patches

*Installation task*: `deploy.kubernetes`

*Can cause reboot*: no

*Can restart service*: always yes, `kubelet`

*OS specific*: No

In `services.kubeadm_patches` section you can override control-plane pod settings as well as kubelet settings on per node basis.
This feature is implemented by using of [kubeadm patches](https://kubernetes.io/docs/setup/production-environment/tools/kubeadm/control-plane-flags/#patches).

**Note**: `patches` feature is available for control-plane pods (etcd, kube-apiserver, kube-controller-manager, kube-scheduler) since Kubernetes **v1.22.0** and for kubelet since Kubernetes **v1.25.0**.

The following is an example of control-plane settings override:
```
services:
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

By default Kubemarine sets `bind-address` parameter of `kube-apiserver` to `node.internal_address` via patches at every control-plane node.

**Note**: If a parameter of control-plane pods is defined in `kubeadm.<service>.extraArgs` or is set by default by kubeadm and then redefined in `kubeadm.paches`, the pod manifest file will contain the same flag twice and the running pod will take into account the last mentioned value (taken from `kubeadm.patches`). This behaviour persists at the moment: https://github.com/kubernetes/kubeadm/issues/1601.

#### kernel_security

This is a common section for `selinux` and `apparmor` properties.

##### selinux

*Installation task*: `prepare.system.setup_selinux`

*Can cause reboot*: Yes, only on configurations change

*Can restart service*: No

*Overwrite files*: Yes, only on configurations change: `/etc/selinux/config`, backup is created

*OS specific*: Yes, performs only on RHEL OS family.

All the SELinux settings are specified in the `services.kernel_security.selinux` section of the inventory.

**Note**: SELinux configuration is possible only on nodes running Centos or RHEL operating system.

The following parameters are available:

<table>
  <tr>
    <th>Name</th>
    <th>Type</th>
    <th>Mandatory</th>
    <th>Default Value</th>
    <th>Possible Values</th>
    <th>Description</th>
  </tr>
  <tr>
    <td rowspan="3"><code>state</code></td>
    <td rowspan="3">string</td>
    <td rowspan="3">no</td>
    <td rowspan="3"><code>enforcing</code></td>
    <td><code>enforcing</code> - The SELinux security policy is enforced.</td>
    <td rowspan="3">Defines the top-level state of SELinux on a system.</td>
  </tr>
  <tr>
    <td><code>permissive</code> - The SELinux system prints warnings but does not enforce policy. This is useful for debugging and troubleshooting purposes.</td>
  </tr>
  <tr>
    <td><code>disabled</code> - SELinux is fully disabled. SELinux hooks are disengaged from the kernel and the pseudo-file system is unregistered.</td>
  </tr>
  <tr>
    <td rowspan="2"><code>policy</code></td>
    <td rowspan="2">string</td>
    <td rowspan="2">no</td>
    <td rowspan="2"><code>targeted</code></td>
    <td><code>targeted</code> - Only targeted network daemons are protected.</td>
    <td rowspan="2">Specifies which policy is currently being enforced by SELinux.</td>
  </tr>
  <tr>
    <td><code>strict</code> - Full SELinux protection, for all daemons. Security contexts are defined, for all subjects and objects, and every single action is processed by,the policy enforcement server.</td>
  </tr>
  <tr>
    <td><code>permissive</code></td>
    <td>list</td>
    <td>no</td>
    <td><pre>- haproxy_t<br>- container_t<br>- keepalived_t</pre></td>
    <td><i>any</i></td>
    <td>Certain SELinux object type policy records, applicable without requiring modification to or recompilation from the policy sources.</td>
  </tr>
</table>

**Warning**: It is recommended to use default values. Using values different from default may cause unexpected consequences and no support is provided for consequences.

**Note**: Turning off and then turning on SELinux can lead to the loss of security rules, which were configured earlier.

For more information about SELinux, refer to the _Official RedHat SELinux Configuration Documentation_ at [https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/html/selinux_users_and_administrators_guide/index](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/html/selinux_users_and_administrators_guide/index).

The procedure for applying SELinux settings is as follows:

1. The current settings on remote hosts are validated first. The detected configurations are precisely compared with the configurations from the inventory:
   * `SELinux status` compared with `services.selinux.state` - Specified if SELinux needs to be disabled or not.
   * `Current mode` and `Mode from config file` compared with the `services.selinux.state` parameter.
   * `Loaded policy name` and `Policy from config file` compared with the `services.selinux.policy` parameter.
   * `Customized Permissive Types` items compared with items in the `services.selinux.permissive` list parameter.
2. If there are no differences, then proceeds with the following tasks.
3. If there is at least one difference, the application of all SELinux settings for remote nodes begins.
4. After applying the settings, it is planned to reboot and re-validate the required configurations.
5. When re-validating, everything is checked again as described in Step 1.

##### apparmor

*Installation task*: `prepare.system.setup_apparmor`

*Can cause reboot*: Yes, only on configurations change.

*Can restart service*: No

*Overwrite files*: Yes, only on configurations change: `/etc/apparmor.d`, no backups.

*OS specific*: Yes, performs only on Ubuntu OS family.

All the AppArmor settings are specified in the `services.kernel_security.apparmor` section of the inventory.

**Note**: AppArmor configuration is possible only on nodes running Ubuntu or Debian operating system.

In the AppArmor section, you must declare the already existing AppArmor profiles, the state of which needs to be changed. It is not necessary to indicate all the available profiles - something that is not indicated is not affected.
The profiles should be specified in a standard way using a path or name. It is possible to modify the following states:

* `enforce` (default mode) - prohibits everything according to the profile settings.
* `complain` - does not prohibit, but only displays violation warnings in the logs.
* `disable` - disables and unloads security profile.

**Note**: The necessary profiles are installed and configured by themselves during the installation of packages and their activation manually is not required by default. However, if some profiles are missing for you, you need to preload them on all nodes yourself and launch the AppArmor task after that.

Example:

```yaml
services:
  kernel_security:
    apparmor:
      enforce:
        - /etc/cron/daily/logrotate
        - /sbin/dhclient
        - nvidia_modprobe
      complain:
        - /usr/lib/postfix/smtp
        - man_filter
      disable:
        - /usr/bin/ping
        - /bin/netstat
        - man_groff 
```

If you need to disable AppArmor, you cannot do this using Kubemarine. If you absolutely need it, you can uninstall AppArmor from the system through the package manager.

**Note**: After the installation of new repositories, the repodata is reloaded.

#### packages

##### package_manager

*Installation task*: `prepare.package_manager.configure`

*Can cause reboot*: No

*Can restart service*: No

*Overwrite files*: Yes, `/etc/yum.repos.d/` or `/etc/apt/sources.list.d/` backup is presented.

*OS specific*: Yes, different defaults for different OS families.

**Warning**: This section is specific to different OS families. Ensure that you use the proper definition format for your OS distributive - it may differ from the presented examples in this document.

If your cluster is in a closed environment or if you need to add additional package manager repositories, you can specify them in the `services.packages.package_manager` section of inventory.
The following parameters are supported:

|Parameter|Default value|Description|
|---|---|---|
|replace-repositories|`false`|Deletes old repositories on hosts and installs new ones instead.|
|repositories| |List of new repositories.|

In the repositories section, you need to specify new repositories to install. The contents of their configurations can be arbitrary and is directly forwarded into the yum repo files.

For example in CentOS:

```yaml
services:
  packages:
    package_manager:
      replace-repositories: true
      repositories:
        kubernetes:
          name: "Kubernetes"
          enabled: 1
          gpgcheck: 0
          baseurl: "https://packages.cloud.google.com/yum/repos/kubernetes-el7-x86_64"
        my_own_repo:
          name: "My repository"
          enabled: 1
          gpgcheck: 1
          baseurl: "https://example.com/repo"
```

For example in Ubuntu:

```yaml
services:
  packages:
    package_manager:
      replace-repositories: true
      repositories:
        - "deb [arch=amd64 trusted=yes] http://example.com/deb/ubuntu/ focal main restricted"
        - "deb [arch=amd64 trusted=yes] http://example.com/deb/ubuntu/ focal-updates main restricted"
        - "deb [arch=amd64 trusted=yes] http://example.com/deb/ubuntu/ focal universe"
        - "deb [arch=amd64 trusted=yes] http://example.com//deb/ubuntu/ focal-updates universe"
        - "deb [arch=amd64 trusted=yes] http://example.com//deb/ubuntu/ focal multiverse"
        - "deb [arch=amd64 trusted=yes] http://example.com/deb/ubuntu/ focal-updates multiverse"
        - "deb [arch=amd64 trusted=yes] http://example.com/deb/ubuntu/ focal-backports main restricted universe multiverse"
        - "deb [arch=amd64 trusted=yes] http://example.com/deb/misc/docker-ce/debian/ buster stable"
```

**Note**: You cannot and do not need to specify repositories for different package managers. The package manager is detected automatically and the specified configuration should match it.

##### management

*Installation task*: `prepare.package_manager.manage_packages`

*Can cause reboot*: Yes, only when a list of installed packages changes.

*Can restart service*: No

*OS specific*: Yes, the necessary package manager is selected for different OS families.

###### mandatory

By default, the installer installs predefined list of mandatory packages from the package manager. The mandatory packages are:
* conntrack
* iptables
* curl
* openssl
* unzip
* semanage
* kmod

The exact package names are detected automatically depending on the OS family of the cluster.
For more information, see [associations](#associations).

**Warning**: Make sure to have all the mandatory packages available in the repositories. 
You can configure the necessary repositories in the [package_manager](#package_manager) section of the inventory.

Most of the mandatory packages are installed on all nodes with the following exceptions:
* conntrack and iptables are installed only on control-plane and worker nodes.
* unzip is installed only on nodes that require thirdparties that are packed in .zip archives.
  For more information, see the **unpack** option in [thirdparties](#thirdparties).
* semanage is installed only on RHEL nodes. 

If you need to turn some mandatory packages off for some reason,
it can be done in the `services.packages.mandatory` section. For example:

```yaml
services:
  packages:
    mandatory:
      conntrack: false
```

###### custom

If you need other custom packages, you can manage them directly during the installation.
You can choose any one of the following types of actions:

* remove
* install
* upgrade

All these actions are performed in a sequence as described above. You can specify only some types of actions or all at once. Short and full configuration formats are available.

**Warning**: Before you start working, ensure to check that you have all the necessary dependencies in the repositories you are using. You can configure the necessary repositories in the [package_manager](#package_manager) section of inventory.

**Warning**: This section is specific to different OS families. Ensure that you use the proper definition format for your OS distributive - it may differ from the presented examples in this document.

**Warning**: The packages in the install section are installed on **all** nodes.

The following is an example to install new packages:

```yaml
services:
  packages:
    install:
      - ethtool
      - ebtables
      - socat
```

The following is an example to install, upgrade, and remove packages:

```yaml
services:
  packages:
    remove:
      - socat
    install:
      - ebtables
    upgrade:
      - ethtool
```

The format of package definition is same as in the package manager. You can specify the exact version of package to install:

```yaml
services:
  packages:
    install:
      - ebtables-2.0.*
      - ethtool-4.*
```

To update all packages, you can use an asterisk. For example:

```yaml
services:
  packages:
    upgrade:
      - *
```

A more complex format is also available in which you can enable and exclude packages from processing:

```yaml
services:
  packages:
    upgrade:
      include:
        - *
      exclude:
        - kernel
        - gluster
```

**Warning**: Be careful with managing packages, they directly affect the host operating system.

**Warning**: If changes in the installed packages list are detected, a reboot is scheduled.

##### associations

*Installation task*: No

*Can cause reboot*: No

*Can restart service*: No

*OS specific*: Yes, different defaults for different OS families.

**Warning**: This section is specific to different OS families. Ensure that you use the proper definition format for your OS distributive - it may differ from the presented examples in this document.

In the `services.packages` section, there is a `services.packages.associations` sub-section that allows you to configure predefined associations of package objects. It allows you to redefine the following knowledges:

* executable_name
* package_name
* service_name
* config_location

This setting is required to change the behavior of the installer such as to install a package with a different name, use the configuration file from the different path, and so on.

**Note**: Associations defaults automatically switches for different OS families. Do not worry about this; use those associations that are specific to your operating system in the common section - specify which one is not required in common cases.

The following associations are used by default:

###### RHEL and Centos

<table>
  <tr>
    <th>Subject</th>
    <th>Association key</th>
    <th>Association value</th>
  </tr>
  <tr>
    <td rowspan="4">docker</td>
    <td>executable_name</td>
    <td>docker</td>
  </tr>
  <tr>
    <td>package_name</td>
    <td>docker-ce-{{k8s-version-specific}}<br/>docker-ce-cli-{{k8s-version-specific}}<br/>containerd.io-{{k8s-version-specific}}</td>
  </tr>
  <tr>
    <td>service_name</td>
    <td>docker</td>
  </tr>
  <tr>
    <td>config_location</td>
    <td>/etc/docker/daemon.json</td>
  </tr>
  <tr>
    <td rowspan="4">containerd</td>
    <td>executable_name</td>
    <td>containerd</td>
  </tr>
  <tr>
    <td>package_name</td>
    <td>containerd.io-{{k8s-version-specific}}</td>
  </tr>
  <tr>
    <td>service_name</td>
    <td>containerd</td>
  </tr>
  <tr>
    <td>config_location</td>
    <td>/etc/containerd/config.toml</td>
  </tr>
  <tr>
    <td rowspan="4">haproxy</td>
    <td>executable_name</td>
    <td>/opt/rh/rh-haproxy18/root/usr/sbin/haproxy</td>
  </tr>
  <tr>
    <td>package_name</td>
    <td>rh-haproxy18-haproxy-{{k8s-version-specific}}</td>
  </tr>
  <tr>
    <td>service_name</td>
    <td>rh-haproxy18-haproxy</td>
  </tr>
  <tr>
    <td>config_location</td>
    <td>/etc/haproxy/haproxy.cfg</td>
  </tr>
  <tr>
    <td rowspan="4">keepalived</td>
    <td>executable_name</td>
    <td>keepalived</td>
  </tr>
  <tr>
    <td>package_name</td>
    <td>keepalived-{{k8s-version-specific}}</td>
  </tr>
  <tr>
    <td>service_name</td>
    <td>keepalived</td>
  </tr>
  <tr>
    <td>config_location</td>
    <td>/etc/keepalived/keepalived.conf</td>
  </tr>
  <tr>
    <td rowspan="4">audit</td>
    <td>executable_name</td>
    <td>auditctl</td>
  </tr>
  <tr>
    <td>package_name</td>
    <td>auditd</td>
  </tr>
  <tr>
    <td>service_name</td>
    <td>auditd</td>
  </tr>
  <tr>
    <td>config_location</td>
    <td>/etc/audit/rules.d/predefined.rules</td>
  </tr>
  <tr>
    <td rowspan="1">conntrack</td>
    <td>package_name</td>
    <td>conntrack-tools</td>
  </tr>
  <tr>
    <td rowspan="1">iptables</td>
    <td>package_name</td>
    <td>iptables</td>
  </tr>
  <tr>
    <td rowspan="1">openssl</td>
    <td>package_name</td>
    <td>openssl</td>
  </tr>
  <tr>
    <td rowspan="1">curl</td>
    <td>package_name</td>
    <td>curl</td>
  </tr>
  <tr>
    <td rowspan="1">unzip</td>
    <td>package_name</td>
    <td>unzip</td>
  </tr>
  <tr>
    <td rowspan="1">kmod</td>
    <td>package_name</td>
    <td>kmod</td>
  </tr>
  <tr>
    <td rowspan="1">semanage</td>
    <td>package_name</td>
    <td>policycoreutils-python</td>
  </tr>
</table>


###### Ubuntu and Debian

<table>
  <tr>
    <th>Subject</th>
    <th>Association key</th>
    <th>Association value</th>
  </tr>
  <tr>
    <td rowspan="4">docker</td>
    <td>executable_name</td>
    <td>docker</td>
  </tr>
  <tr>
    <td>package_name</td>
    <td>docker-ce={{k8s-version-specific}}<br/>docker-ce-cli={{k8s-version-specific}}<br/>containerd.io={{k8s-version-specific}}</td>
  </tr>
  <tr>
    <td>service_name</td>
    <td>docker</td>
  </tr>
  <tr>
    <td>config_location</td>
    <td>/etc/docker/daemon.json</td>
  </tr>
  <tr>
    <td rowspan="4">containerd</td>
    <td>executable_name</td>
    <td>containerd</td>
  </tr>
  <tr>
    <td>package_name</td>
    <td>containerd={{k8s-version-specific}}</td>
  </tr>
  <tr>
    <td>service_name</td>
    <td>containerd</td>
  </tr>
  <tr>
    <td>config_location</td>
    <td>/etc/containerd/config.toml</td>
  </tr>
  <tr>
    <td rowspan="4">haproxy</td>
    <td>executable_name</td>
    <td>/usr/sbin/haproxy</td>
  </tr>
  <tr>
    <td>package_name</td>
    <td>haproxy={{k8s-version-specific}}</td>
  </tr>
  <tr>
    <td>service_name</td>
    <td>haproxy</td>
  </tr>
  <tr>
    <td>config_location</td>
    <td>/etc/haproxy/haproxy.cfg</td>
  </tr>
  <tr>
    <td rowspan="4">keepalived</td>
    <td>executable_name</td>
    <td>keepalived</td>
  </tr>
  <tr>
    <td>package_name</td>
    <td>keepalived={{k8s-version-specific}}</td>
  </tr>
  <tr>
    <td>service_name</td>
    <td>keepalived</td>
  </tr>
  <tr>
    <td>config_location</td>
    <td>/etc/keepalived/keepalived.conf</td>
  </tr>
  <tr>
    <td rowspan="4">audit</td>
    <td>executable_name</td>
    <td>auditctl</td>
  </tr>
  <tr>
    <td>package_name</td>
    <td>auditd</td>
  </tr>
  <tr>
    <td>service_name</td>
    <td>auditd</td>
  </tr>
  <tr>
    <td>config_location</td>
    <td>/etc/audit/rules.d/predefined.rules</td>
  </tr>
  <tr>
    <td rowspan="1">conntrack</td>
    <td>package_name</td>
    <td>conntrack</td>
  </tr>
  <tr>
    <td rowspan="1">iptables</td>
    <td>package_name</td>
    <td>iptables</td>
  </tr>
  <tr>
    <td rowspan="1">openssl</td>
    <td>package_name</td>
    <td>openssl</td>
  </tr>
  <tr>
    <td rowspan="1">curl</td>
    <td>package_name</td>
    <td>curl</td>
  </tr>
  <tr>
    <td rowspan="1">unzip</td>
    <td>package_name</td>
    <td>unzip</td>
  </tr>
  <tr>
    <td rowspan="1">kmod</td>
    <td>package_name</td>
    <td>kmod</td>
  </tr>
</table>

**Note**: 
* By default, the packages' versions are installed according to the Kubernetes version specified in the [Supported versions](#supported-versions) section.
* In the procedure for adding nodes, the package versions are taken from the current nodes to match the nodes in the cluster.
  For example, if `containerd.io-1.6.4-1` is installed on the nodes of the cluster, this version is installed on the new node.
  This behavior can be changed by setting the `cache_versions` option to "false".
  The package versions are then used only with the template from the `associations` section.
  The option can be used both in global `services.packages` and in specific associations sections.

The following is an example of overriding docker associations:

```yaml
services:
  packages:
    cache_versions: true
    associations:
      docker:
        cache_versions: false
        executable_name: 'docker'
        package_name:
          - docker-ce-19*
          - docker-ce-cli-19*
          - containerd.io-1.4.3-3.1*
        service_name: 'docker'
        config_location: '/etc/docker/daemon.json'
```

In case when you should redefine associations for multiple OS families at once, you should define their names in the root of `associations` in the following way:

```yaml
services:
  packages:
    cache_versions: true
    associations:
      debian:
        haproxy:
          executable_name: '/usr/sbin/haproxy'
          package_name: haproxy=1.8.*
      rhel:
        haproxy:
          executable_name: '/opt/rh/rh-haproxy18/root/usr/sbin/haproxy'
          package_name: rh-haproxy18-haproxy-1.8*
```

**Note**: There are only 3 supported OS families: Debian, RHEL, and RHEL8 (for RHEL based version 8).

#### thirdparties

*Installation task*: `prepare.thirdparties`

*Can cause reboot*: No

*Can restart service*: No

*Overwrite files*: Yes, backup is not presented

*OS specific*: No

The installer has a mechanism to automatically deliver files from third party sources and install them in the system.
For example, using it is convenient to automatically download a certain file from a repository and place it in a specific place in the system.
This is configured in the `services.thirdparties` section. The contents of this section are as follows:
* The absolute destination path on the host system of the cluster is indicated as a key
* A set of the following parameters is indicated as values:

|Name|Mandatory|Default Value|Description|
|---|---|---|---|
|**source**|**yes**| |Source from where to upload the file to hosts. It can be an URL or an **absolute** path on the deployment node. For detailed description of this parameter, see [Installation without Internet Resources](#installation-without-internet-resources).|
|**sha1**|no|`None`|SHA1 hash of the file. It is necessary in order to check with an existing file on the hosts and decide whether to download the file or not.|
|**owner**|no|`root`|The owner who needs to be assigned to the file after downloading it.|
|**mode**|no|`700`|The mode which needs to be assigned to the file after downloading it.|
|**unpack**|no|`None`|Absolute path on hosts where to unpack the downloaded file. Unpacking is supported only for the following file extensions: `.tar.gz` and `.zip`.|
|**group**|no|`None`|The name of the group to whose hosts the file should be uploaded.|
|**groups**|no|`None`|The list of group names to whose hosts the file should be uploaded.|
|**node**|no|`None`|The name of node where the file should be uploaded.|
|**nodes**|no|`None`|The list of node names where the file should be uploaded.|

**Warning**: verify that you specified the path to the correct version of the thirdparty.

**Note**: Groups and nodes can be combined.

**Note**: If no groups and nodes are present, then the file is uploaded to control-planes and workers by default.

**Note**: If the file is already uploaded to hosts and its hash matches with the hash in the config, then the file is not downloaded again.

**Note**: The installation of the thirdparties sources that are required in the plugins are installed with the plugin. For more information, see [thirdparty](#thirdparty).

By default, the installer installs the following thirdparties with the following configuration:

```yaml
services:
  thirdparties:
    /usr/bin/kubeadm:
      source: 'https://storage.googleapis.com/kubernetes-release/release/{{k8s-version}}/bin/linux/amd64/kubeadm'
    /usr/bin/kubelet:
      source: 'https://storage.googleapis.com/kubernetes-release/release/{{k8s-version}}/bin/linux/amd64/kubelet'
    /usr/bin/kubectl:
      source: 'https://storage.googleapis.com/kubernetes-release/release/{{k8s-version}}/bin/linux/amd64/kubectl'
      group: control-plane
    /usr/bin/calicoctl:
      source: 'https://github.com/projectcalico/calico/releases/download/{{calico-version}}/calicoctl-linux-amd64'
      group: control-plane
    # "crictl" is installed by default ONLY if "containerRuntime != docker", otherwise it is removed programmatically
    /usr/bin/crictl.tar.gz:
      source: 'https://github.com/kubernetes-sigs/cri-tools/releases/download/{{crictl-version}}/crictl-{{crictl-version}}-linux-amd64.tar.gz'
      group: control-plane
      unpack: /usr/bin/
```

If necessary, you can redefine or add thirdparties. For example:

```yaml
services:
  thirdparties:
    /usr/bin/kubeadm:
      source: https://example.com/kubernetes/kubeadm/v1.22.2/bin/linux/amd64/kubeadm
```

#### CRI

*Installation task*: `prepare.cri`

*Can cause reboot*: No

*Can restart service*: Always yes, `docker` or `containerd`

*Overwrite files*: Yes, by default `/etc/docker/daemon.json` or `/etc/containerd/config.toml`, `/etc/crictl.yaml` and `/etc/containers/registries.conf`, backup is created. 
Additionally, if  `plugins."io.containerd.grpc.v1.cri".registry.config_path` is defined in `services.cri.containerdConfig` specified directory will be created and filled according `services.cri.containerdRegistriesConfig`.

*OS specific*: No

The `services.cri` section configures container runtime used for kubernetes. By default, the following parameters are used:

```yaml
services:
  cri:
    containerRuntime: containerd
    containerdConfig:
      version: 2
      plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runc:
        runtime_type: "io.containerd.runc.v2"
      plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runc.options:
        SystemdCgroup: true
      # This parameter is added, if no registry.mirrors and registry.configs.tls specified:
      plugins."io.containerd.grpc.v1.cri".registry:
        config_path: "/etc/containerd/certs.d"
    dockerConfig:
      ipv6: False
      log-driver: json-file
      log-opts:
        max-size: 64m
        max-file: "3"
      exec-opts:
        - native.cgroupdriver=systemd
      icc: False
      live-restore: True
      userland-proxy: False
```

**Note**: default value of `SystemdCgroup` = `true` only in case, when `cgroupDriver` from [kubelet config](#kubeadm_kubelet) is equal to `systemd`.

The `containerRuntime` parameter configures a particular container runtime implementation used for kubernetes.
The available values are `docker` and `containerd`. By default `containerd` is used.

When containerd is used as a container runtime, it is possible to additionally define the `containerdConfig` section,
which contains the parameters passed to `config.toml`, for example:

```yaml
services:
  cri:
    containerRuntime: containerd
    containerdConfig:
      plugins."io.containerd.grpc.v1.cri":
        sandbox_image: registry.k8s.io/pause:3.2
```

Also, it is possible to specify registries configuration in registries hosts format using `containerdRegistriesConfig` section:
```yaml
services:
  cri:
    containerRuntime: containerd
    containerdRegistriesConfig:
      artifactory.example.com:5443:
        host."https://artifactory.example.com:544":
          capabilities: [ "pull", "resolve" ]
```

If `containerdRegistriesConfig` is specified, registries hosts configuration is placed in `/etc/containerd/certs.d` directory by default.
It's possible to override this value `plugins."io.containerd.grpc.v1.cri".registry.config_path` in `containerdConfig`:
```yaml
services:
  cri:
    containerRuntime: containerd
    containerdConfig:
      plugins."io.containerd.grpc.v1.cri".registry:
        config_path: "/etc/containerd/registries"
    containerdRegistriesConfig:
      artifactory.example.com:5443:
        host."https://artifactory.example.com:544":
          capabilities: [ "pull", "resolve" ]
```

**Note**: it's possible to specify registries using `registry.mirrors` and `registries.configs.tls`, but it's not recommended, 
because this approach is deprecated by containerd team since containerd v1.5.0:
```yaml
services:
  cri:
    containerRuntime: containerd
    containerdConfig:
      plugins."io.containerd.grpc.v1.cri".registry.mirrors."artifactory.example.com:5443":
        endpoint:
        - https://artifactory.example.com:5443
      plugins."io.containerd.grpc.v1.cri".registry.configs."artifactory.example.com:5443".tls:
        insecure_skip_verify: true
```

**Note**: `registry.mirrors` and `registries.configs.tls` can't be used with `config_path` or `containerdRegistriesConfig`
because it's restricted by containerd. In that case kubemarine fails with exception during enrichment.

Although, `registry.mirrors` and `registries.configs` are deprecated, when the registry requires an authentication, 
it should be specified using `registries.configs.auth`, as in following example:

```yaml
services:
  cri:
    containerRuntime: containerd
    containerdConfig:
      plugins."io.containerd.grpc.v1.cri".registry.configs."private-registry:5000".auth:
        auth: "bmMtdXNlcjperfr="
    containerdRegistriesConfig:
      private-registry:5000:
        host."https://private-registry:5000":
          capabilities: [ "pull", "resolve" ]
          skip_verify: true
```

Where, `auth: "bmMtdXNlcjperfr="` field is `username:password` string in base64 encoding.

Note how `containerdConfig` and `containerdRegistriesConfig.<registry>` sections reflect the toml format structure.
For more details on containerd configuration, refer to the official containerd configuration file documentation at [https://github.com/containerd/containerd/blob/main/docs/cri/config.md](https://github.com/containerd/containerd/blob/main/docs/cri/config.md).
By default, the following parameters are used for `containerdConfig`:

```yaml
services:
  cri:
    containerdConfig:
      version: 2
      plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runc:
        runtime_type: "io.containerd.runc.v2"
      plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runc.options:
        SystemdCgroup: true
      # This parameter is added, if no registry.mirrors and registry.configs.tls specified:
      plugins."io.containerd.grpc.v1.cri".registry:
        config_path: "/etc/containerd/certs.d"
```

**Note**: When containerd is used, `crictl` binary is also installed and configured as required.

Alternatively, it is possible to use docker as a container runtime for kubernetes by setting `docker` value for `containerRuntime` parameter.
When docker is used as a container runtime, it is possible to additionally define the `dockerConfig` section,
which contains the parameters passed to `daemon.json`, for example:

```yaml
services:
  cri:
    containerRuntime: docker
    dockerConfig:
      insecure-registries:
        - artifactory.example.com:5443
      registry-mirrors:
        - https://artifactory.example.com:5443
```

For detailed description of the parameters, see [Installation without Internet Resources](#installation-without-internet-resources).
For more information about Docker daemon parameters, refer to the official docker configuration file documentation at [https://docs.docker.com/engine/reference/commandline/dockerd/#daemon-configuration-file](https://docs.docker.com/engine/reference/commandline/dockerd/#daemon-configuration-file).

**Note**: After applying the parameters, the docker is restarted on all nodes in the cluster.

**Note**: Do not omit the `containerRuntime` parameter in cluster.yaml if you include `dockerConfig` or `containerdConfig` in `cri` section

#### modprobe

*Installation task*: `prepare.system.modprobe`

*Can cause reboot*: Yes, only when a list of kernel modules changes.

*Can restart service*: No

*Overwrite files*: Yes, only when a list of kernel modules changes, `/etc/modules-load.d/predefined.conf`, backup is created

*OS specific*: Yes

The `services.modprobe` section manages Linux Kernel modules to be loaded in the host operating system. By default, the following modules are loaded(according to the IP version and OS family):

IPv4:
```yaml
services:
  modprobe:
    rhel:
    - br_netfilter
    rhel8:
    - br_netfilter
    debian:
    - br_netfilter
```

IPv6:
```yaml
services:
  modprobe:
    rhel:
    - br_netfilter
    - ip6table_filter
    - nf_conntrack_ipv6
    - nf_nat_masquerade_ipv6
    - nf_reject_ipv6
    - nf_defrag_ipv6
    rhel8:
    - br_netfilter
    - ip6table_filter
    - nf_conntrack
    - nf_nat
    - nf_reject_ipv6
    - nf_defrag_ipv6
    debian:
    - br_netfilter
    - ip6table_filter
    - nf_conntrack
    - nf_nat
    - nf_reject_ipv6
    - nf_defrag_ipv6
```

If necessary, you can redefine or add [List Merge Strategy](#list-merge-strategy) to the standard list of Kernel modules to load. For example (Debian OS family):

```yaml
services:
  modprobe:
    debian:
      - my_own_module1
      - my_own_module2
```

**Warning**: Be careful with these settings, they directly affect the hosts operating system.

**Warning**: If changes to the hosts `modprobe` configurations are detected, a reboot is scheduled. After the reboot, the new parameters are validated to match the expected configuration.

#### sysctl

*Installation task*: `prepare.system.sysctl`

*Can cause reboot*: Yes, only when list of Kernel parameters changes.

*Can restart service*: No

*Overwrite files*: Yes, only when list of Kernel parameters changes: `/etc/sysctl.d/98-kubemarine-sysctl.conf`, backup is created

*OS specific*: No

The `services.sysctl` section manages the Linux Kernel parameters for all hosts in a cluster. By default, the following key-values are configured:

|Key|Value|Note|
|---|---|---|
|net.bridge.bridge-nf-call-iptables|1| |
|net.ipv4.ip_forward|1| |
|net.ipv4.ip_nonlocal_bind|1| |
|net.ipv4.conf.all.route_localnet|1| |
|net.bridge.bridge-nf-call-ip6tables|1|Presented only when IPv6 detected in node IP|
|net.ipv6.conf.all.forwarding|1|Presented only when IPv6 detected in node IP|
|net.ipv6.ip_nonlocal_bind|1|Presented only when IPv6 detected in node IP|
|kernel.panic|10||
|vm.overcommit_memory|1||
|kernel.panic_on_oops|1||
|kernel.pid_max|calculated| If this parameter is not explicitly indicated in the `cluster.yaml`, then this value is calculated by this formula: `maxPods * podPidsLimit + 2048` |

Constant value equal to `2048` means the maximum number of processes that the system can require during run (only processes of the Linux virtual machine itself are implied). This value have been established empirically.

**Note**: You can also define the `kernel.pid_max` value by your own, but you need to be sure that it is at least greater than the result of the expression: `maxPods * podPidsLimit + 2048`. For more information about the `podPidsLimit` and `maxPods` values, refer to the [kubeadm_kubelet](#kubeadm_kubelet) section. 

**Warning**: Also, in both the cases of calculation and manual setting of the `pid_max` value, the system displays a warning if the specified value is less than the system default value equal to `32768`. If the `pid_max` value exceeds the maximum allowable value of `4194304`, the installation is interrupted.

**Note**: Before Kubernetes 1.21 `sysctl` property `net.ipv4.conf.all.route_localnet` have been set automatically to `1` by Kubernetes, but now it setting by Kubemarine defaults. [Kubernetes 1.21 Urgent Upgrade Notes](https://github.com/kubernetes/kubernetes/blob/control-plane/CHANGELOG/CHANGELOG-1.21.md#no-really-you-must-read-this-before-you-upgrade-6).

You can specify your own parameters instead of the standard parameters. You need to specify the parameter key and its value. If the value is empty, the key is ignored. For example:

```yaml
services:
  sysctl:
    net.bridge.bridge-nf-call-iptables: 1
    net.ipv4.ip_forward: 0
    net.ipv4.ip_nonlocal_bind: 0
```

**Warning**: Be careful with these settings, they directly affect the hosts operating system.

**Warning**: If the changes to the hosts `sysctl` configurations are detected, a reboot is scheduled. After the reboot, the new parameters are validated to match the expected configuration.

#### audit

##### Audit Kubernetes Policy

*Installation task*: `deploy.kubernetes.audit`

*Can cause reboot*: No

*Can restart service*: Always yes, container kube-apiserver.

*Overwrite files*: Yes, `/etc/kubernetes/audit-policy.yaml` backup is created.

*OS specific*: No

For more information about Kubernetes auditing, refer to the official documentation at [https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/](https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/).

**Logging level**:
`None` - do not log;
`Metadata` — log request metadata: user, request time, target resource (pod, namespace, etc.), action type (verb), etc.;
`Request` — log metadata and request body;
`RequestResponse` - log metadata, request body and response body.

**omitStages**: The list of stages for which no events are created.

By default, the following policy is installed:

<details>
  <summary>Default Policy</summary>

```yaml
services:
  audit:
    cluster_policy:
      apiVersion: audit.k8s.io/v1
      kind: Policy
      # Don't generate audit events for all requests in RequestReceived stage.
      omitStages:
        - "RequestReceived"
      rules:
        # Don't log read-only requests
        - level: None
          verbs: ["watch", "get", "list"]
        # Don't log checking access by internal services
        - level: None
          userGroups:
            - "system:serviceaccounts:calico-apiserver"
            - "system:nodes"
          verbs: ["create"]
          resources:
            - group: "authorization.k8s.io"
              resources: ["subjectaccessreviews"]
            - group: "authentication.k8s.io"
              resources: ["tokenreviews"]
        # Don't log update of ingress-controller-leader ConfigMap by ingress-nginx.
        # This reproduces only for v1.2.0 and can be removed after its support stop.
        - level: None
          users: ["system:serviceaccount:ingress-nginx:ingress-nginx"]
          verbs: ["update"]
          resources:
            - group: ""
              resources: ["configmaps"]
              resourceNames: ["ingress-controller-leader"]
        # Log all other resources in core and extensions at the request level.
        - level: Metadata
          verbs: ["create", "update", "patch", "delete", "deletecollection"]
          resources:
          - group: ""
            resources:
            - configmaps
            - endpoints
            - limitranges
            - namespaces
            - nodes
            - persistentvolumeclaims
            - persistentvolumes
            - pods
            - replicationcontrollers
            - resourcequotas
            - secrets
            - serviceaccounts
            - services
          - group: "apiextensions.k8s.io"
            resources:
            - customresourcedefinitions
          - group: "apps"
            resources:
            - daemonsets
            - deployments
            - replicasets
            - statefulsets
          - group: "batch"
            resources:
            - cronjobs
            - jobs
          - group: "policy"
            resources:
            - podsecuritypolicies
          - group: "rbac.authorization.k8s.io"
            resources:
            - clusterrolebindings
            - clusterroles
            - rolebindings
            - roles
          - group: "autoscaling"
            resources:
            - horizontalpodautoscalers
          - group: "storage.k8s.io"
            resources:
            - storageclasses
            - volumeattachments
          - group: "networking.k8s.io"
            resources:
            - ingresses
            - ingressclasses
            - networkpolicies
          - group: "authentication.k8s.io"
            resources: ["tokenreviews"]
          - group: "authorization.k8s.io"
          - group: "projectcalico.org"
            resources:
              - bgpconfigurations
              - bgpfilters
              - bgppeers
              - blockaffinities
              - caliconodestatuses
              - clusterinformations
              - felixconfigurations
              - globalnetworkpolicies
              - globalnetworksets
              - hostendpoints
              - ipamconfigurations
              - ippools
              - ipreservations
              - kubecontrollersconfigurations
              - networkpolicies
              - networksets
              - profiles
          - group: "crd.projectcalico.org"
            resources:
              - bgpconfigurations
              - bgpfilters
              - bgppeers
              - blockaffinities
              - caliconodestatuses
              - clusterinformations
              - felixconfigurations
              - globalnetworkpolicies
              - globalnetworksets
              - hostendpoints
              - ipamblocks
              - ipamconfigs
              - ipamhandles
              - ippools
              - ipreservations
              - kubecontrollersconfigurations
              - networkpolicies
              - networksets
```
</details>

It is possible not only to redefine the default policy, but also to extend it. For more information, refer to [List Merge Strategy](#list-merge-strategy).

For example, consider you have an [operator](https://kubernetes.io/docs/concepts/extend-kubernetes/operator/) that constantly updates some Pods' labels and some ConfigMap to maintain the leadership.
If you do not see any benefit from logging of such events, they can be disabled by specifying the following in `cluster.yaml`:

```yaml
services:
  audit:
    cluster_policy:
      rules:
      - level: None
        userGroups: ["system:serviceaccounts:operator-namespace"]
        verbs: ["patch", "update"]
        namespaces: ["operator-namespace"]
        resources:
        - group: ""
          resources: [pods]
        - group: ""
          resources: [configmaps]
          resourceNames: [controller-leader]
      - '<<': merge
```

##### Audit Daemon

*Installation tasks*:
* `prepare.system.audit.install`
* `prepare.system.audit.configure`

*Can cause reboot*: No

*Can restart service*: Always yes, `auditd`.

*OS specific*: No

```yaml
services:
  audit:
    rules:
      - -w /var/lib/docker -k docker
      - -w /etc/docker -k docker
      - -w /usr/lib/systemd/system/docker.service -k docker
      - -w /usr/lib/systemd/system/docker.socket -k docker
      - -w /etc/default/docker -k docker
      - -w /etc/docker/daemon.json -k docker
      - -w /usr/bin/containerd -k docker
      - -w /usr/sbin/runc -k docker
      - -w /usr/bin/dockerd -k docker
```

Except `-w /usr/bin/containerd -k docker`, all the other rules are applied only when the `docker` container runtime is used.

#### ntp

This is a common section for `chrony` and `timesyncd` properties.

For Kubernetes and ETCD to work correctly, it is recommended to configure the system time synchronization on all nodes of the cluster. However, this is optional and you can do it at your own discretion.

##### chrony

*Installation task*: `prepare.ntp.chrony`

*Can cause reboot*: No

*Can restart service*: Always yes, `chronyd`

*Overwrite files*: Yes, `/etc/chrony.conf`, backup is created

*OS specific*: Yes, performs only on the RHEL OS family.

**Warning:** incorrect time synchronization can lead to incorrect operation of the cluster or services. You can validate
the time synchronization via the [Time difference](Kubecheck.md#218-time-difference) test between the nodes from 
[PAAS Check procedure](Kubecheck.md#paas-procedure).

To synchronize the system time, you must make a list of NTP servers. All servers must be accessible from any node of the cluster.
The list should be indicated in the `chrony` section of the` services.ntp` section config file.
In addition to the NTP server address, you can specify any additional configurations in the same line. 

The following parameters are supported:

|Name|Mandatory|Type|Default value|Description|
|---|---|---|---|---|
|servers|**yes**|list| |NTP servers addresses with additional configurations.|
|makestep|no|string|`5 -1`|Step the system clock if large correction is needed.|
|rtcsync|no|boolean|`True`|Specify that RTC should be automatically synchronized by kernel.|

For more information about Chrony configuration, refer to the official documentation at [https://chrony.tuxfamily.org/documentation.html](https://chrony.tuxfamily.org/documentation.html).

The following is a configuration example:

```yaml
services:
  ntp:
    chrony:
      servers:
        - ntp1.example.com iburst
        - ntp2.example.com iburst
```

An example is also available in [Full Inventory Example](../examples/cluster.yaml/full-cluster.yaml).

Synchronization is configured with the` prepare.ntp.chrony` task. The task performs the following:
* Generates the `chrony.conf` file and uploads it to the `/etc/chrony` directory on all cluster hosts. If dumping is enabled, the config dump is saved.
* Restarts the `chronyd.service` service
* Checks if the synchronization is done by the first host of the cluster. Leap status should become normal.

If the configuration `services.ntp.chrony.servers` is absent, then the task` prepare.ntp.chrony` in the installation is skipped.

##### timesyncd

*Installation task*: `prepare.ntp.timesyncd`

*Can cause reboot*: No

*Can restart service*: Always yes, `systemd-timesyncd`.

*Overwrite files*: Yes, `/etc/systemd/timesyncd.conf`, backup is created.

*OS specific*: Yes, performs only on Debian OS family.

**Warning:** incorrect time synchronization can lead to incorrect operation of the cluster or services. You can validate
the time synchronization via the [Time difference](Kubecheck.md#218-time-difference) test between the nodes from 
[PAAS Check procedure](Kubecheck.md#paas-procedure).

To synchronize the system time, you must make a list of NTP servers. All servers must be accessible from any node of the cluster.
The list should be indicated in the `timesyncd.Time.NTP` parameter of the` services.ntp` section config file.
In addition to the NTP server address, you can specify any additional configurations in the same line. 

The following parameters are supported:

|Name|Mandatory|Type|Default value|Description|
|---|---|---|---|---|
|NTP|**yes**|list| |NTP servers addresses.|
|FallbackNTP|**no**|list| |Backup NTP servers addresses when NTP servers are unavailable.|
|RootDistanceMaxSec|no|int|`5`|Step the system clock if large correction is needed.|
|PollIntervalMinSec|no|int|`32`|The minimal poll interval.|
|PollIntervalMaxSec|no|int|`2048`|The maximum poll interval.|

The following is a configuration example:

```yaml
services:
  ntp:
    timesyncd:
      Time:
        NTP:
          - ntp1.example.com
          - ntp2.example.com
```

Synchronization is configured with the` prepare.ntp.timesyncd` task. The task performs the following:

* Generates the `timesyncd.conf` file and uploads it to the `/etc/systemd/` directory on all cluster hosts. If dumping is enabled, the config dump is saved.
* Restarts the `systemd-timesyncd` service.
* Checks if the synchronization is done by the first host of the cluster. The leap status should become normal.

If the configuration `services.ntp.timesyncd.servers` is absent, then the task` prepare.ntp.timesyncd` in the installation is skipped.

#### resolv.conf

*Installation task*: `prepare.dns.resolv_conf`

*Can cause reboot*: No

*Can restart service*: No

*Overwrite files*: Yes, `/etc/resolv.conf`, backup is created

*OS specific*: No

The `services.resolv.conf` section allows you to configure the nameserver addresses to which cluster systems has access. By default, this section is empty in the inventory. The following parameters are supported:

|Name|Type|Description|
|---|---|---|
|search|string|The domain name to search|
|nameservers|list|The DNS servers for usage in the OS|

**Note**: 
* If some network resources are located in a restricted network and are not resolved through the standard DNS, be sure to configure this section and specify your custom DNS service.
* Do not put ${cluster_name} in the `search` field, otherwise some microservices might work incorrectly.

For example:

```yaml
services:
  resolv.conf:
    search: default
    nameservers:
      - 1.1.1.1
      - 1.0.0.1
      - 2606:4700:4700::1111
      - 2606:4700:4700::1001
```

#### etc_hosts

*Installation task*: `prepare.dns.etc_hosts`

*Can cause reboot*: no

*Can restart service*: no

*Overwrite files*: Yes, `/etc/hosts`, backup is created

*OS specific*: No

The installation procedure has a task that generates and applies `/etc/hosts` configuration file on all nodes presented in the cluster.

**Warning**: This task overwrites the existing original `/etc/hosts` file records on all hosts. If you need to save these records, manually move them into inventory file to `serives.etc_hosts` section.

By default, the generated file contains the following address associations:

* Localhost for IPv4 and IPv6
* Internal control-plain address as `control-plain` and FQDN name
* Balancers, control-planes, workers names and theirs FQDNs

In order to setup your custom address, you need to specify the IP-address as the key and DNS-name as the list item. Example:

```yaml
services:
  etc_hosts:
    1.1.1.1:
      - example.com
```

Example of generated file:

```
127.0.0.1        localhost localhost.localdomain localhost4 localhost.localdomain4
::1              localhost localhost.localdomain localhost6 localhost6.localdomain6
1.1.1.1          example.com
100.100.100.101  k8s-stack.example.com control-plain balancer-1.k8s-stack.sdntest.example.com balancer-1
100.100.100.102  control-plane-1.k8s-stack.example.com control-plane-1
100.100.100.103  control-plane-2.k8s-stack.example.com control-plane-2
100.100.100.104  control-plane-3.k8s-stack.example.com control-plane-3
100.100.100.105  worker-1.k8s-stack.example.com worker-1
100.100.100.106  worker-2.k8s-stack.example.com worker-2
100.100.100.107  worker-3.k8s-stack.example.com worker-3
```

You can specify multiple addresses at once, for example:

```yaml
services:
  etc_hosts:
    1.1.1.1:
      - example.com
      - demo.example.com
```

This generates the following result:

```
...
1.1.1.1          example.com demo.example.com
...
```

It is possible to define custom names for internal and external ip addresses of the cluster nodes. In this case /etc/hosts file at the nodes will contain 2 lines about the same IP address.
For example, setting the following in the `cluster.yaml`:

```
services:
  etc_hosts:
    100.100.100.102:  another-name-for-control-plane-1
```

will lead to the following content of /etc/hosts:

```
...
100.100.100.102  another-name-for-control-plane-1
...

100.100.100.102  control-plane-1.k8s-stack.example.com control-plane-1
...
```

#### coredns

`coredns` parameter configures the Coredns service and its DNS rules in the Kubernetes cluster. It is divided into the following sections:

##### add_etc_hosts_generated

This is a boolean parameter defining whether IP addresses of the cluster nodes and their generated domain names should be added to `coredns.configmap.Hosts`.
Default is `true`.

##### configmap

This section contains the Configmap parameters that are applied to the Coredns service. By default the following configs are used:

* Corefile - The main Coredns config, which is converted into a template in accordance with the specified parameters.
* Hosts - IP addresses and names in the format of `/etc/hosts` file. Can be customized with any desired IP addresses and names. 
Default value is 

```
127.0.0.1 localhost localhost.localdomain
::1 localhost localhost.localdomain
'
``` 

If `services.coredns.add_etc_hosts_generated` is set to `true`, `Hosts` is enriched with generated list of IP addresses and names of the cluster nodes.

If `Hosts` is redefined in the `cluster.yaml` its default value is overridden. 

Before working with the Corefile, refer to the official Coredns plugins documentation at [https://coredns.io/plugins/](https://coredns.io/plugins/).

The Corefile consists of the settings applied for a specific destination. By default, all settings are applied for `.:53` destination. 
For example:

```yaml
services:
  coredns:
    configmap:
      Corefile:
        '.:53':
          errors: True
          rewrite: # Not used by default, intended for GEO distributed scheme
            default:
              priority: 1
              data:
                name:
                - regex
                - (.*)\.cluster-1\.local {1}.cluster.local
                answer:
                - name
                - (.*)\.cluster\.local {1}.cluster-1.local
```

The following settings are supported:

<table>
<thead>
  <tr>
    <th>Parameter</th>
    <th>Type<br></th>
    <th>Default value</th>
    <th>Description</th>
  </tr>
</thead>
<tbody>
  <tr>
    <td>errors</td>
    <td>boolean</td>
    <td>True</td>
    <td>Any errors encountered during the query processing are printed to standard output. The errors of a particular type can be consolidated and printed once per a period of time</td>
  </tr>
  <tr>
    <td>health</td>
    <td>boolean</td>
    <td>True</td>
    <td>Enabled process wide health endpoint. When CoreDNS is up and running, this returns a 200 OK HTTP status code. The health is exported, by default, on port 8080/health.</td>
  </tr>
  <tr>
    <td>ready</td>
    <td>boolean</td>
    <td>True</td>
    <td>By enabling ready, an HTTP endpoint on port 8181 returns 200 OK when all plugins that are able to signal readiness have done so. If some are not ready, the endpoint still returns a 503 with the body containing the list of plugins that are not ready. Once a plugin has signaled that it is ready, it is not queried again.</td>
  </tr>
  <tr>
    <td>prometheus</td>
    <td>string</td>
    <td>:9153</td>
    <td>With Prometheus, you export metrics from the CoreDNS and any plugin that has them. The metrics path is fixed to /metrics</td>
  </tr>
  <tr>
    <td>cache</td>
    <td>integer</td>
    <td>30</td>
    <td>With cache enabled, all records except zone transfers and metadata records are cached according to the ttl value set</td>
  </tr>
  <tr>
    <td>loop</td>
    <td>boolean</td>
    <td>True</td>
    <td>The loop plugin sends a random probe query and keeps a track of how many it is viewed. If it is viewed more than twice, assume that CoreDNS has seen a forwarding loop and halt the process.</td>
  </tr>
  <tr>
    <td>reload</td>
    <td>boolean</td>
    <td>True</td>
    <td>This plugin allows automatic reload of a changed Corefile.</td>
  </tr>
  <tr>
    <td>loadbalance</td>
    <td>boolean<br></td>
    <td>True</td>
    <td>The loadbalance acts as a round-robin DNS load balancer by randomizing the order of A, AAAA, and MX records in the answer.</td>
  </tr>
  <tr>
    <td>rewrite [continue|stop]</td>
    <td>dict</td>
    <td>Not provided</td>
    <td>The rewrite could be used for rewriting different parts of DNS questions and answers. By default, it is not used, but it is required to use rewrite plugin in DR schema. It is possible to use `rewrite continue` or `rewrite stop` to define the `rewrite` plugin behaviour in case of multiple rules. Refer to the [official documentation](https://coredns.io/plugins/rewrite/) for more details. </td>
  </tr>
  <tr>
    <td>hosts</td>
    <td>dict</td>
    <td>/etc/coredns/Hosts</td>
    <td>The hosts plugin is useful for serving zones from a /etc/hosts like file. It serves from a preloaded file, which is applied from ConfigMap during the installation.</td>
  </tr>
  <tr>
    <td>forward</td>
    <td>list</td>
    <td>- .<br>- /etc/resolv.conf</td>
    <td>The forward plugin re-uses already opened sockets to the upstreams. It supports UDP, TCP, and DNS-over-TLS. It is used in band health checking.</td>
  </tr>
  <tr>
    <td>kubernetes</td>
    <td>dict</td>
    <td></td>
    <td>This plugin implements the Kubernetes DNS-Based Service Discovery Specification. Refer the following sections for more details.</td>
  </tr>
  <tr>
    <td>template</td>
    <td>dict</td>
    <td></td>
    <td>The template plugin allows you to dynamically respond to queries by just writing a template. Refer the following sections for more details.</td>
  </tr>
</tbody>
</table>

**Note**: 

* Some settings allow multiple entries. For example, `template`. If necessary, different priority can be set for different template sections. For example:
```
          template:
            test-example-com:
              enabled: true
              priority: 1
              class: IN
              type: A
              zone: 'test.example.com'
              data:
                answer: '{% raw %}{{ .Name }}{% endraw %} 100 IN A 1.1.1.1'
            example-com:
              priority: 2
              enabled: true
              class: IN
              type: A
              zone: 'example.com'
              data:
                answer: '{% raw %}{{ .Name }}{% endraw %} 100 IN A 2.2.2.2'

```
The lesser the priority value, the earlier in `Corefile` config this entry appears. Default priority is `1`.

* DNS resolving is done according to the [hardcoded plugin chain](https://github.com/coredns/coredns/blob/v1.8.0/plugin.cfg). This specifies that a query goes through `template`, then through `hosts`, then through `kubernetes`, and then through `forward`. By default, Corefile contains the `template` setting, which resolves all names like `*.{{ cluster_name }}` in the vIP address. Hence despite entries in `Hosts`, such names are resolved in the vIP address.
* You can set any setting parameter to `False` to disable it, no matter what type it is.
* It is possible to specify other Corefile settings in an inventory-like format. However, this is risky since the settings have not been tested with the generator. All non-supported settings have a lower priority.

**Warning**: It is strongly discouraged to change the configuration of the CoreDNS manually, if you need to change the configuration, you must reflect them in the `cluster.yaml` and call the installation procedure with `--tasks="deploy.coredns"` argument. This will help keep the cluster configuration consistent.

##### deployment

This section contains YAML settings that are applied to Coredns service via a patch. By default, this section contains the following data:

```yaml
services:
  coredns:
    deployment:
      spec:
        template:
          spec:
            volumes:
            - configMap:
                defaultMode: 420
                items:
                - key: Corefile
                  path: Corefile
                - key: Hosts
                  path: Hosts
                name: coredns
              name: config-volume
```

However, it is possible to add or modify any deployment parameters of the inventory in accordance with the Kubernetes patching syntax.

#### loadbalancer

`loadbalancer` configures the balancers for the Kubernetes cluster. Currently, only the Haproxy configuration can be customized.

###### target_ports

This section describes the ports, which are used for http/https connections from balancer nodes to workers. 
Those parameters are specified as backend ports in haproxy configuration and as host ports in ingress-nginx-controller plugin.

Default values depend on balancer availability:  

<table>
<thead>
  <tr>
    <th>Parameter</th>
    <th>Type<br></th>
    <th>Default value if balancer is presented </th>
    <th>Default value in no-balancer clusters </th>
  </tr>
</thead>
<tbody>
  <tr>
    <td>target_ports.http</td>
    <td>integer</td>
    <td>20080</td>
    <td>80</td>
  </tr>
  <tr>
    <td>target_ports.https</td>
    <td>integer</td>
    <td>20443</td>
    <td>443</td>
  </tr>
</tbody>
</table>

If it is needed, those parameters can be overriden in `cluster.yaml`, e.g.:
```yaml
services:
  loadbalancer:
    target_ports:
      http: 80
      https: 443
```

##### haproxy

This section describes the configuration parameters that are applied to the **haproxy.cfg** config file, and also some Kubemarine related parameters.
By default, the following configuration is used:

```yaml
services:
  loadbalancer:
    haproxy:
      global:
        maxconn: 10000
      defaults:
        timeout_connect: '10s'
        timeout_client: '1m'
        timeout_server: '1m'
        timeout_tunnel: '60m'
        timeout_client_fin: '1m'
        maxconn: 10000
      keep_configs_updated: True
```

These settings can be overrided in the **cluster.yaml**. Currently, the following settings of **haproxy.cfg** are supported:

<table>
<thead>
  <tr>
    <th>Parameter</th>
    <th>Type<br></th>
    <th>Default value</th>
    <th>Description</th>
  </tr>
</thead>
<tbody>
  <tr>
    <td>global.maxconn</td>
    <td>integer</td>
    <td>10000</td>
    <td>"maxconn". Set the total number of connections allowed, process-wide.</td>
  </tr>
  <tr>
    <td>defaults.timeout_connect</td>
    <td>string</td>
    <td>10s</td>
    <td>"timeout connect". Set the maximum time to wait for a connection attempt to a server to succeed.</td>
  </tr>
  <tr>
    <td>defaults.timeout_client</td>
    <td>string</td>
    <td>1m</td>
    <td>"timeout client". Set the maximum inactivity time on the client side.</td>
  </tr>
  <tr>
    <td>defaults.timeout_server</td>
    <td>string</td>
    <td>1m</td>
    <td>"timeout server". Set the maximum inactivity time on the server side.</td>
  </tr>
  <tr>
    <td>defaults.timeout_tunnel</td>
    <td>string</td>
    <td>60m</td>
    <td>"timeout tunnel". Set the maximum inactivity time on the client and server sides for tunnels.</td>
  </tr>
  <tr>
    <td>defaults.timeout_client_fin</td>
    <td>string</td>
    <td>1m</td>
    <td>"timeout client-fin". Set the inactivity timeout on the client side for half-closed connections.</td>
  </tr>
  <tr>
    <td>defaults.maxconn</td>
    <td>integer</td>
    <td>10000</td>
    <td>"maxconn". Limits the sockets to this number of concurrent connections.</td>
  </tr>
  <tr>
    <td>keep_configs_updated</td>
    <td>boolean</td>
    <td>True</td>
    <td>Allows Kubemarine update haproxy configs every time, when cluster (re)installed or it's schema updated (added/removed nodes)</td>
  </tr>
  <tr>
    <td>config</td>
    <td>string</td>
    <td></td>
    <td>Custom haproxy config value to be used instead of the default one.</td>
  </tr>
  <tr>
    <td>config_file</td>
    <td>string</td>
    <td></td>
    <td>Path to the Jinja-template file with custom haproxy config to be used instead of the default one.</td>
  </tr>
  <tr>
    <td>maintenance_mode</td>
    <td>boolean</td>
    <td>False</td>
    <td>Enable maintenance config for HAproxy</td>
  </tr>
  <tr>
    <td>mntc_config_location</td>
    <td>string</td>
    <td>/etc/haproxy/haproxy_mntc.cfg</td>
    <td>Maintenance config flie location</td>
  </tr>
</tbody>
</table>

For more information on Haproxy-related parameters, refer to the official Haproxy documentation at [https://www.haproxy.org/download/1.8/doc/configuration.txt](https://www.haproxy.org/download/1.8/doc/configuration.txt).

**Note**: you can use either `config` or `config_file` if you need to use custom config instead of default.

Parameter `config` allows to specify your custom config file. The priority of this option is higher than that of `config_file`, and if both are specified, `config` will be used. Example:

```yaml
services:
  loadbalancer:
    haproxy:
      keep_configs_updated: True
      config: "global
    log /dev/log    local0
    log /dev/log    local1 notice
    chroot /var/lib/haproxy
    stats socket /run/haproxy/admin.sock mode 660 level admin expose-fd listeners
    stats timeout 30s
    user haproxy
    group haproxy
    daemon

    ca-base /etc/ssl/certs
    crt-base /etc/ssl/private

    ssl-default-bind-ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384
    ssl-default-bind-ciphersuites TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256
    ssl-default-bind-options ssl-min-ver TLSv1.2 no-tls-tickets

defaults
    log     global
    mode    http
    option  httplog
    option  dontlognull
    timeout connect 5000
    timeout client  50000
    timeout server  50000
    errorfile 400 /etc/haproxy/errors/400.http
    errorfile 403 /etc/haproxy/errors/403.http
    errorfile 408 /etc/haproxy/errors/408.http
    errorfile 500 /etc/haproxy/errors/500.http
    errorfile 502 /etc/haproxy/errors/502.http
    errorfile 503 /etc/haproxy/errors/503.http
    errorfile 504 /etc/haproxy/errors/504.http"
```

Parameter `config_file` allows to specify path to Jinja-compiled template. Example:
```yaml
services:
  loadbalancer:
    haproxy:
      keep_configs_updated: True
      config_file: '/root/my_haproxy_config.cfg.j2'
```

This parameter use the following context options for template rendering:
- nodes
- bindings
- config_options
- target_ports

As an example of a template, you can look at [default template](/kubemarine/templates/haproxy.cfg.j2).

#### maintenance mode

Kubemarine supports maintenance mode for HAproxy balancer. HAproxy balancer has additional configuration file for that purpose. The following configuration enable maintenance mode for balancer:

```yaml
services:
  loadbalancer:
    haproxy:
      maintenance_mode: True
      mntc_config_location: '/etc/haproxy/haproxy_mntc_v1.cfg'
```

### RBAC Admission

*Installation task*: `deploy.admission`

There are two options for admissions, `psp` and `pss`. PodSecurityPolicy (PSP) is being deprecated in Kubernetes 1.21 and will be removed in Kubernetes 1.25. Kubernetes 1.23 supports Pod Security Standards (PSS) that are implemented as a feature gate of `kube-apiserver`. Since Kubernetes v1.25 does not support PSP, the installation and maintenance procedures assume that the `cluster.yaml` file includes `admission: pss` explicitly.  
By default, Kubemarine uses `psp` rbac admission value for Kubernetes version 1.24 or lower and `pss` value for version 1.25+.

```yaml
rbac:
  admission: psp
```

### Admission psp

Pod security policies enable fine-grained authorization of pod creation and updates.
Pod security policies are enforced by enabling the admission controller. By default, admission controller is enabled during installation.

To configure pod security policies it is required to provide cluster-level `policy/v1beta1/podsecuritypolicy` resource 
that controls security sensitive aspects of the pod specification. 
If controller is enabled and no policies are provided, then the system does not allow deployment of new pods.
Several OOB policies are provided and by default they are enabled during installation. 
It is also possible to specify custom policies to be applied during installation. 

Configuration format for `psp` section is as follows:

```yaml
rbac:
  admission: psp
  psp:
    pod-security: enabled
    oob-policies:
      default: enabled
      host-network: enabled
      anyuid: enabled
    custom-policies:
      psp-list: []
      roles-list: []
      bindings-list: []
```

#### Configuring Admission Controller

Admission controller is enabled by default during installation.
It is possible to disable admission controller installation to fully disable pod security policy enforcement.
In this case no OOB or custom policies are installed. To disable admission controller:

```yaml
rbac:
  admission: psp
  psp:
    pod-security: disabled
```

**Note**: 

* Disabling admission controller is not recommended.
* On existing cluster it is possible to enable/disable admission controller using the `manage_psp` maintenance procedure.

#### Configuring OOB Policies

The following policies are provided and enabled out of the box:

<table>
    <tr><th>Policy name</th><th>PSP, CR, CRB names</th><th>Use case</th></tr>
    <tr>
        <td>privileged</td>
        <td><ul>
            <li><code>oob-privileged-psp</code></li>
            <li><code>oob-privileged-psp-cr</code></li>
            <li><code>oob-privileged-psp-crb</code></li>
        </ul></td>
        <td>Used for pods which require full privileges, for example kube-system pods</td>
    </tr>
    <tr>
        <td>default</td>
        <td><ul>
            <li><code>oob-default-psp</code></li>
            <li><code>oob-default-psp-cr</code></li>
            <li><code>oob-default-psp-crb</code></li>
        </ul></td>
        <td>Used for <code>authenticated</code> group, enforces unauthorized users to deploy pods with severe restrictions</td>
    </tr>
    <tr>
        <td>anyuid</td>
        <td><ul>
            <li><code>oob-anyuid-psp</code></li>
            <li><code>oob-anyuid-psp-cr</code></li>
        </ul></td>
        <td>Used for pods which require root privileges</td>
    </tr>
    <tr>
        <td>host-network</td>
        <td><ul>
            <li><code>oob-host-network-psp</code></li>
            <li><code>oob-host-network-psp-cr</code></li>
        </ul></td>
        <td>Used for pods which require host network access</td>
    </tr>
</table>


The OOB policies are not installed if admission controller is disabled. 
You can manually disable a particular OOB policy during installation, except `privileged` policy.

For example, to disable `host-network` OOB policy:

```yaml
rbac:
  admission: psp
  psp:
    oob-policies:
      host-network: disabled
```

**Note**: 

* Disabling OOB policies is not recommended. 
* `PodSecurityPolicy` (PSP) resources included in different OOB policies are used by different OOB plugins, so disabling any OOB policy may lead to **issues with some OOB plugins**. 
  If you are using OOB plugins then you should provide custom PSPs in place of disabled OOB PSPs and bind them using `ClusterRoleBinding` to particular plugin `ServiceAccout`.
* It is possible to reconfigure OOB policies on an existing cluster using the `manage_psp` maintenance procedure.

#### Configuring Custom Policies

You can install custom policies during cluster installation. For example, to install custom "most restricted" policy for `authenticated` group:

```yaml
rbac:
  admission: psp
  psp:
    custom-policies:
      psp-list:
      - apiVersion: policy/v1beta1
        kind: PodSecurityPolicy
        metadata:
          name: most-restricted-psp
          annotations:
            seccomp.security.alpha.kubernetes.io/allowedProfileNames: 'docker/default,runtime/default'
            seccomp.security.alpha.kubernetes.io/defaultProfileName:  'runtime/default'
        spec:
          privileged: false
          # Allow core volume types.
          hostPID: false
          hostIPC: false
          hostNetwork: false
          volumes:
            - 'configMap'
            - 'emptyDir'
            - 'projected'
            - 'secret'
            - 'downwardAPI'
            - 'persistentVolumeClaim'
          fsGroup:
            rule: 'MustRunAs'
            ranges:
              - min: 1
                max: 65535
          readOnlyRootFilesystem: true
          runAsUser:
            rule: 'MustRunAsNonRoot'
          supplementalGroups:
            rule: 'MustRunAs'
            ranges:
              - min: 1
                max: 65535
          runAsGroup:
            rule: 'MustRunAs'
            ranges:
              - min: 1
                max: 65535
          allowPrivilegeEscalation: false
          seLinux:
            rule: 'RunAsAny'
          requiredDropCapabilities:
            - ALL
      roles-list:
      - apiVersion: rbac.authorization.k8s.io/v1
        kind: ClusterRole
        metadata:
          name: most-restricted-psp-cr
        rules:
          - apiGroups: ['policy']
            resources: ['podsecuritypolicies']
            verbs:     ['use']
            resourceNames:
              - most-restricted-psp
      bindings-list:
      - kind: ClusterRoleBinding
        apiVersion: rbac.authorization.k8s.io/v1
        metadata:
          name: most-restricted-psp-crb
        roleRef:
          kind: ClusterRole
          name: most-restricted-psp-cr
          apiGroup: rbac.authorization.k8s.io
        subjects:
          - kind: ServiceAccount
            # it is possible to bind to non-existing SA in non-existing namespace
            name: sa-name
            namespace: sa-namespace
```

**Note**:

* Any of these lists can be empty.
* If the list is not empty, then all the resources should align with list type. For example, the `psp-list` can only have resources with `kind: PodSecurityPolicy`.
* The custom policies should not have 'oob-' prefix.
* To manage custom policies on an existing cluster use the `manage_psp` maintenance procedure. 

### Admission pss

Pod Security Standards (PSS) are the replacement for Pod Security Policies (PSP). Originally PSS assumes only three levels 
(or profiles) of policies. The profiles are the following:
* `Privileged`	- Unrestricted policy, providing the widest possible level of permissions. This policy allows for known privilege 
escalations.
* `Baseline`	- Minimally restrictive policy which prevents known privilege escalations. Allows the default (minimally specified) 
Pod configuration.
* `Restricted`	- Heavily restricted policy, following current Pod hardening best practices.

There are plenty of rules that included in `baseline` and `restricted` profiles. For more information, refer to 
[Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/).

**Note**:

* PSS are supported for Kubernetes versions higher than 1.23.
* To enable PSS, define `admission: pss` explicitly in cluster.yaml:

```yaml
rbac:
  admission: pss
```

#### Configuring Default Profiles

The following configuration is default for PSS:

```yaml
rbac:
  admission: pss
  pss:
    pod-security: enabled
    defaults:
      enforce: baseline
      enforce-version: latest
      audit: baseline
      audit-version: latest
      warn: baseline
      warn-version: latest
    exemptions:
      usernames: []
      runtimeClasses: []
      namespaces: ["kube-system"]
```

There are three parts of PSS configuration: 
* `pod-security` enables or disables the PSS installation.
* The default profile is described in the `defaults` section and `enforce` defines the policy standard that enforces the pods.
* `exemptions` describes the exemptions from default rules.

PSS enabling requires special labels for plugin namespaces such as `nginx-ingress-controller`, `kubernetes-dashboard`, `local-path-provisioner`, and `calico` (relevant only for `calico-apiserver` namespace). For instance:

```yaml
apiVersion: v1
kind: Namespace
metadata:
  labels:
    pod-security.kubernetes.io/enforce: privileged
    pod-security.kubernetes.io/enforce-version: latest
    pod-security.kubernetes.io/audit: privileged
    pod-security.kubernetes.io/audit-version: latest
    pod-security.kubernetes.io/warn: privileged
    pod-security.kubernetes.io/warn-version: latest
```

In case of enabling predefined plugins the labels will be set during the installation procedure automatically.

**Warnings**: 
Pay attention to the fact that for Kubernetes versions higher than v1.23 the PSS option implicitly enabled by default in 
`kube-apiserver` [Feature Gates](https://kubernetes.io/docs/reference/command-line-tools-reference/feature-gates/).
Therefor PSS labels on namespaces shouldn't be set even if you Kubernetes cluster is deployed without PSS enabled.

#### Configuring Exemptions

The `exemption` section describes objects that are not enforced by the policy. It is possible to define `User` or `ServiceAccount` in 
the `username` section. For example, ("system:serviceaccount:my-ns:myadmin" - it is a serviceAccount, "myuser" - it is a user):

```yaml
...
    exemptions:
      usernames: ["system:serviceaccount:my-ns:myadmin", "myuser"]
```

In this case, `kube-apiserver` does not enforce the default policy to any pods that are created by `myuser` or `myadmin`.

The default configuration does not enforce the default policy to any of the pods in the `kube-system` namespace.

```yaml
...
    exemptions:
      namespaces: ["kube-system"]
```

Do not change the namespaces exemption list without strong necessary. In any case check our maintenance guide before any implementation.

#### Application prerequisites

In case of using PSS the application that installed in Kubernetes cluster should be matched with PSS profiles (`privileged`, 
`baseline`, `restricted`). Those profiles may be set by labeling the namespace so as it described above for predefined plugins. 
Moreover the application should be compatible with PSS. The `restricted` profile requires the following section in pod description:

```yaml
...
securityContext: 
  runAsNonRoot: true
  seccompProfile: 
    type: "RuntimeDefault"
  allowPrivilegeEscalation: false
  capabilities: 
    drop: ["ALL"]
...
```

### RBAC Accounts

*Installation task*: `deploy.accounts`

In the `deploy.accounts` section, you can specify the account creation settings after the cluster is installed.

### RBAC account_defaults

In this section, you can describe any parameters that needs to be applied by default to each record in the [RBAC accounts](#rbac-accounts) section. It works the same way as [node_defaults](#node_defaults).

The default settings for `account_defaults` are as follows:

```yaml
rbac:
  account_defaults:
    namespace: kube-system
    configs:
      - apiVersion: v1
        kind: ServiceAccount
        metadata: {}
      - apiVersion: rbac.authorization.k8s.io/v1
        kind: ClusterRoleBinding
        metadata: {}
        roleRef:
          apiGroup: rbac.authorization.k8s.io
          kind: ClusterRole
        subjects:
          - kind: ServiceAccount
      - apiVersion: v1
        kind: Secret
        metadata:
          annotations: {}
        type: kubernetes.io/service-account-token
```

The yaml file that is created from the above template is applied to the cluster during the installation procedure.

**Note**: The `Secret` section works only for Kubernetes v1.24. It is excluded for Kubernetes v1.23 and lower versions.

### Plugins

*Installation task*: `deploy.plugins`

In the `plugins` section, you can configure the parameters of plugins, as well as register your own plugins. Plugins are installed during the `deploy.plugins` task.
If you skip the plugin installation task, no plugins are installed.

#### Predefined Plugins

When you want to install a plugin, the installer includes pre-configured plug-in configurations. The following plugins are available for installation out of the box:

* Network plugins
  * [calico](#calico)
* Ingress Controllers
  * [nginx-ingress-controller](#nginx-ingress-controller)
* [kubernetes-dashboard](#kubernetes-dashboard)
* [local-path-provisioner](#local-path-provisioner)

**Note**: It is not possible to install multiple plugins of the same type at the same time.

##### calico

Before proceeding, refer to the [Official Documentation of the Kubernetes Cluster Network](https://kubernetes.io/docs/concepts/cluster-administration/networking/).

Calico plugin is installed by default and does not require any special enablement or configuration. However it is possible to explicitly enable or disable the installation of this plugin through the `install` plugin parameter.

**Warning**: According to the Calico kernel requirements, CentOS 7 with a kernel lower than `3.10.0-940.el7.x86_64` is not compatible with Calico 3.24 and higher. For more information, refer to [Kubernetes requirements](https://docs.tigera.io/calico/3.24/getting-started/kubernetes/requirements#kubernetes-requirements).

The following is an example to enable the calico plugin:

```yaml
plugins:
  calico:
    install: true
```

The following is an example to disable the calico plugin:

```yaml
plugins:
  calico:
    install: false
```

After applying the plugin configurations, the plugin installation procedure waits for the following pods to be in the `Running` state:
* coredns
* calico-kube-controllers
* calico-node
* calico-apiserver

If the pods do not have time to start at a specific timeout, then the plugin configuration is incorrect. In this case, the installation is aborted.

By default, no additional settings are required for the plugin. However, you can change the default settings. To do this, in the `plugins` section of the config file, specify the `calico` plugin section and list all the necessary parameters and their values in it.
For example:

```yaml
plugins:
  calico:
    install: true
    mtu: 1400
    typha:
      enabled: true
      nodeSelector:
        region: infra
    node:
      image: calico/node:v3.10.1
    env:
      FELIX_USAGEREPORTINGENABLED: 'true'

```

An example is also available in [Full Inventory Example](../examples/cluster.yaml/full-cluster.yaml).

###### Calico BGP Configuration

By default, calico is installed with "full mesh" BGP topology, that is, every node has BGP peering with all other nodes in the cluster. If the cluster size is more than 50 nodes it is recommended to use the BGP configuration with route reflectors instead of full mesh.
You also have to change calico BGP configuration if you are using DR schema.

**Note**: change BGP topology is possible for calico v3.20.1 or higher.

To enable route reflector and/or DR topology during installation the next steps are required:

1. Choose the nodes to be route reflectors and add the label `route-reflector: True` to their description in the cluster.yaml. It is recommended to use control-plane nodes for route reflectors, but not necessarily.

2. Add required parameters in the `calico` plugin section:
```yaml
plugins:
  calico:
    fullmesh: false            # Full mesh will not be used, RRs will be used instead
    announceServices: true     # ClusterIP services CIDR will be announced through BGP
    defaultAsNumber: 65200     # AS Number will be 65200 for all nodes by default
    globalBgpPeers:            # Additional global BGP Peer(s) will be configured with given IP and AS Number
    - ip: 192.168.17.1
      as: 65200
```

It is also possible to change BGP topology at the running cluster. 

**Warning**: short downtime is possible during BGP peering sessions reestablishing.

To switch from "full mesh" to "route reflector" topology:
- add the label `route-reflector: True` to the route reflector nodes manually:
```
$ kubectl label node <NODENAME> route-reflector=True
```
- add `fullmesh: false` parameter to the `calico` plugin section in the cluster.yaml
- run `kubemarine install` with the `deploy.plugins` task only. Other plugins should have `install: false` in the cluster.yaml at this step.

**Note**: for the topology with route reflectors the predefined value `routeReflectorClusterID=244.0.0.1` is used.

To switch from "route reflector" to "full mesh" topology:
- change `fullmesh` parameter value to `true` in the `calico` plugin section in the cluster.yaml (it also may be removed so the default value of `fullmesh` is being used)
- run `kubemarine install` with the `deploy.plugins` task only. Other plugins should have `install: false` in the cluster.yaml at this step
- remove the labels `route-reflector: true` from the route reflector nodes manually:
```
$ kubectl label node <NODENAME> route-reflector-
```
If necessary, remove `route-reflector` label from the cluster.yaml as well.


**Warning**: For correct network communication, it is important to set the correct MTU value (For example in case `ipip` mode it should be 20 bytes less than MTU NIC size), see more details in [Troubleshooting Guide](Troubleshooting.md#packets-between-nodes-in-different-networks-are-lost).

**Note**: If the cluster size is more than 3 nodes, Calico Typha daemon is enabled by default and number of its replicas is incremented with every 50 nodes. This behavior can be overridden with cluster.yaml.

The plugin configuration supports the following parameters:

| Name                   | Type    | Default Value                       | Value Rules                                      | Description                                                        |
|------------------------|---------|-------------------------------------|--------------------------------------------------|--------------------------------------------------------------------|
| mode                   | string  | `ipip`                              | `ipip` / `vxlan`                                 | Network protocol to be used in network plugin                      |
| crossSubnet            | boolean | `true`                              | true/false                                       | Enables crossing subnet boundaries to improve network performance  |
| mtu                    | int     | `1440`                              | MTU size on interface - 50                       | MTU size for Calico interface                                      |
| fullmesh               | boolean | true                                | true/false                                       | Enable or disable full mesh BGP topology                           |
| announceServices       | boolean | false                               | true/false                                       | Enable announces of ClusterIP services CIDR through BGP            |
| defaultAsNumber        | int     | 64512                               |                                                  | AS Number to be used by default for the cluster                  |
| globalBgpPeers         | list    | []                                  | list of (IP,AS) pairs                            | List of global BGP Peer (IP,AS) values                             |
| typha.enabled          | boolean | `true` or `false`                   | If nodes < 4 then `false` else `true`            | Enables the [Typha Daemon](https://github.com/projectcalico/typha) |
| typha.replicas         | int     | <code>{{ (((nodes&#124;length)/50) + 2) &#124; round(1) }}</code> | Starts from 2 replicas and increments for every 50 nodes | Number of Typha running replicas. |
| typha.image            | string  | `calico/typha:{calico.version}`     | Should contain both image name and version       | Calico Typha image                                                 |
| typha.tolerations      | list    | [Default Typha Tolerations](#default-typha-tolerations) | list of extra tolerations    | Additional custom tolerations for calico-typha pods                |
| cni.image              | string  | `calico/cni:{calico.version}`                | Should contain both image name and version | Calico CNI image                                                |
| node.image             | string  | `calico/node:{calico.version}`               | Should contain both image name and version | Calico Node image                                               |
| kube-controllers.image | string  | `calico/kube-controllers:{calico.version}`   | Should contain both image name and version | Calico Kube Controllers image                                   |
| kube-controllers.tolerations | list | Original kube-controllers tolerations     | list of extra tolerations                  | Additional custom toleration for calico-kube-controllers pods   |
| flexvol.image          | string  | `calico/pod2daemon-flexvol:{calico.version}` | Should contain both image name and version | Calico Flexvol image                                            |
| apiserver.image        | string  | `calico/apiserver:{calico.version}`          | Should contain both image name and version | Calico API server image                                         |
| apiserver.tolerations  | list    | Original API server tolerations              | list of extra tolerations                  | Additional custom toleration for calico-apiserver pods          |

###### Default Typha Tolerations

```yaml
- key: CriticalAddonsOnly
  operator: Exists
- key: node.kubernetes.io/network-unavailable
  effect: NoSchedule
- key: node.kubernetes.io/network-unavailable
  effect: NoExecute
```
**Note**: The `CriticalAddonsOnly` toleration key inherits from `Calico` manifest YAML, whereas the rest of toleration keys are represented by Kubemarine itself.

###### Calico metrics configuration

By default, no additional settings are required for Calico metrics. They are enabled by default.

**Note**: The following ports are opened for metrics: `calico-node` : `9091`, `calico-kube-controllers` : `9094`, and `calico-typha`: `9093`.
The ports for `calico-node` and `calico-typha` are opened on the host.
These ports are currently not configurable by means of Kubemarine.

**Note**: If you use [prometheus-operator](https://github.com/prometheus-operator/prometheus-operator) or its resources in your monitoring solution,
you can use the following ServiceMonitors to collect metrics from Calico:

<details>
  <summary>Click to expand</summary>

```yaml
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  labels:
    # If you use prometheus-operator,
    # specify the custom label corresponding to the configuration of your Prometheus.serviceMonitorSelector.
    # The same is for the other ServiceMonitors below.
    app.kubernetes.io/component: monitoring
  name: calico-metrics
  namespace: kube-system
spec:
  endpoints:
    # You can configure custom scraping properties, but leave `port: metrics`.
    # The same is for the other ServiceMonitors below.
    - interval: 30s
      port: metrics
      scrapeTimeout: 10s
  namespaceSelector:
    matchNames:
      - kube-system
  selector:
    matchLabels:
      k8s-app: calico-node
---
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  labels:
    app.kubernetes.io/component: monitoring
  name: calico-kube-controllers-metrics
  namespace: kube-system
spec:
  endpoints:
    - interval: 30s
      port: metrics
      scrapeTimeout: 10s
  namespaceSelector:
    matchNames:
      - kube-system
  selector:
    matchLabels:
      k8s-app: calico-kube-controllers
---
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  labels:
    app.kubernetes.io/component: monitoring
  name: calico-typha-metrics
  namespace: kube-system
spec:
  endpoints:
    - interval: 30s
      port: metrics
      scrapeTimeout: 10s
  namespaceSelector:
    matchNames:
      - kube-system
  selector:
    matchLabels:
      k8s-app: calico-typha-metrics
```
</details>

###### Calico Environment Properties

It is possible to change the default Calico environment properties. To do that, it is required to specify a key-value in the `env` section in the `calico` plugin definition. For example:

```
plugins:
  calico:
    env:
      WAIT_FOR_DATASTORE: 'false'
      FELIX_DEFAULTENDPOINTTOHOSTACTION: DENY
```

**Note**: In case of you use IPv6 you have to define `CALICO_ROUTER_ID` with value `hash` in `env` section. This uses a hash of the configured nodename for the router ID.

For more information about the supported Calico environment variables, refer to the official Calico documentation at [https://docs.projectcalico.org/reference/node/configuration](https://docs.projectcalico.org/reference/node/configuration).

###### Calico API server

For details about the Calico API server, refer to the official documentation at [https://docs.tigera.io/calico/latest/operations/install-apiserver](https://docs.tigera.io/calico/latest/operations/install-apiserver).

By default, the Calico API server is not installed. To install it during the Calico installation, specify the following:

```yaml
plugins:
  calico:
    apiserver:
      enabled: true
```

**Note**: Calico API server requires its annual certificates' renewal.
For more information, refer to [Configuring Certificate Renew Procedure for calico](/documentation/Maintenance.md#configuring-certificate-renew-procedure-for-calico).

Kubemarine waits for the API server availability during the installation.
If the default wait timeout does not fit, it can be extended in the same `apiserver` section of the `calico` plugin.

```yaml
plugins:
  calico:
    apiserver:
      expect:
        apiservice:
          retries: 60
```

The following parameters are supported:

| Name                                  | Type | Mandatory | Default Value | Example | Description                                          |
|-------------------------------------- |------|-----------|---------------|---------|------------------------------------------------------|
| `apiserver.expect.apiservice.timeout` | int  | no        | 5             | `10`    | Number of retries for the API service expect check.  |
| `apiserver.expect.apiservice.retries` | int  | no        | 40            | `60`    | Timeout for the API service expect check in seconds. |

##### nginx-ingress-controller

Before proceeding, refer to the [Official Documentation of the Kubernetes Ingress Controllers](https://kubernetes.io/docs/concepts/services-networking/ingress-controllers/) and visit [official Nginx Ingress Controller repository](https://github.com/nginxinc/kubernetes-ingress).

NGINX Ingress Controller plugin is installed by default and does not require any special enablement or configuration. However, you can explicitly enable or disable the installation of this plugin through the `install` plugin parameter.

The following is an example to enable the plugin:

```yaml
plugins:
  nginx-ingress-controller:
    install: true
```

The following is an example to disable the plugin:

```yaml
plugins:
  nginx-ingress-controller:
    install: false
```

After applying the plugin configurations, the plugin installation procedure waits for the `nginx-ingress-controller` pod to be in the `Running` state.

If the pods do not have time to start at a specific timeout, then the plugin configuration is incorrect. In this case, the installation is aborted.

By default, no additional settings are required for the plugin. However, you can change the default settings. To do this, in the `plugins` section of the config file, specify the `nginx-ingress-controller` plugin section and list all the necessary parameters and their values ​​in it.
For example:

```yaml
plugins:
  nginx-ingress-controller:
    install: true
    controller:
      image: k8s-artifacts-prod/ingress-nginx/controller:v0.34.1
```

An example is also available in [Full Inventory Example](../examples/cluster.yaml/full-cluster.yaml).

The plugin configuration supports the following parameters:

* The `controller.image` parameter specifies the string for the NGINX Ingress Controller image.
* The `controller.ssl.enableSslPassthrough` parameter is used to enable the ssl-passthrough feature. The default value is `false`. 
**Note**: Enabling this feature introduces a small performance penalty. 

* The `controller.ssl.default-certificate` parameter is used to configure a custom default certificate for ingress resources.
The certificate and key are provided using one of the following two formats:

  * The `controller.ssl.default-certificate.data` format is used to provide a certificate and a key inplace in the pem format:
    
    ```yaml
      nginx-ingress-controller:
      controller:
        ssl:
          default-certificate:
            data:
              cert: |
                -----BEGIN CERTIFICATE-----
                ... (skipped) ...
                -----END CERTIFICATE-----
              key: |
                -----BEGIN RSA PRIVATE KEY-----
                ... (skipped) ...
                -----END RSA PRIVATE KEY-----
    ```
    
  * The `controller.ssl.default-certificate.paths` format is used to provide a certificate and a key as paths to the pem files:
   
    ```yaml
      nginx-ingress-controller:
      controller:
        ssl:
          default-certificate:
            paths:
              cert: /path/to/cert
              key: /path/to/key
    ```
* The `config_map` parameter is used to customize or fine tune NGINX behavior. Before proceeding, refer to the [Official NGINX Ingress Controller documentation](https://kubernetes.github.io/ingress-nginx/user-guide/nginx-configuration/configmap/)
For example:    
```yaml
  nginx-ingress-controller:
    config_map:
      server-tokens: "False"
```
Default config_map settings:

<table>
<thead>
  <tr>
    <th>Parameter</th>
    <th>Default value if balancer is presented </th>
    <th>Default value in no-balancer clusters </th>
  </tr>
</thead>
<tbody>
  <tr>
    <td>allow-snippet-annotations</td>
    <td>"true"</td>
    <td>"true"</td>
  </tr>
  <tr>
    <td>use-proxy-protocol</td>
    <td>"true"</td>
    <td>"false"</td>
  </tr>
</tbody>
</table>

**Warning**: Ingress-nginx and HAproxy use proxy protocol in the default configuration. If you are using a load balancer without a proxy protocol, it **must** also be disabled in ingress-nginx. To do this, specify `use-proxy-protocol: "false"` in configmap.

* The `custom_headers` parameter sets specified custom headers before sending the traffic to backends. Before proceeding, refer to the official NGINX Ingress Controller documentation at [https://kubernetes.github.io/ingress-nginx/user-guide/nginx-configuration/configmap/](https://kubernetes.github.io/ingress-nginx/user-guide/nginx-configuration/configmap/).

For example:    

```yaml
  nginx-ingress-controller:
    custom_headers:
      Expect: $http_expect
      X-Different-Name: "true"
      X-Request-Start: t=${msec}
      X-Using-Nginx-Controller: "true"
```

* The `args` parameter is used to add cli arguments to ingress-nginx-controller. Before proceeding, refer to the official NGINX Ingress Controller documentation at [https://kubernetes.github.io/ingress-nginx/user-guide/cli-arguments/](https://kubernetes.github.io/ingress-nginx/user-guide/cli-arguments/).

For example:
```yaml
  nginx-ingress-controller:
    controller:
      args: ['--disable-full-test', '--disable-catch-all']
```

**Warning**: Arguments for ingress-nginx-controller are also added from [nginx-ingress-controller-v*-original.yaml](https://github.com/Netcracker/KubeMarine/blob/main/kubemarine/plugins/yaml/), from other parameters in cluster.yaml (`controller.ssl.enableSslPassthrough` and `controller.ssl.default-certificate`) and `--watch-ingress-without-class=true` is added by default. Make sure there are no conflicts, otherwise the task will be interrupted.

###### monitoring
By default 10254 port is opened and provides Prometheus metrics.

##### kubernetes-dashboard

Before proceeding, refer to the [Official Documentation of the Kubernetes Dashboard UI](https://kubernetes.io/docs/tasks/access-application-cluster/web-ui-dashboard/) and visit [official Kubernetes Dashboard repository](https://github.com/kubernetes/dashboard).

By default, the Kubernetes dashboard is not installed, as it is not a mandatory part of the cluster. However, you can install it by enabling the plugin.

The following is an example to enable dashboard plugin:

```yaml
plugins:
  kubernetes-dashboard:
    install: true
```

**Note**: By default Kubernetes dashboard is available at `dashboard.{{ cluster_name }}`.

**Note**: The Kubernetes Dashboards UI is available **only** via HTTPS.

If you enable the plugin, all other parameters are applied by default. The following is a list of supported parameters:

<table>
  <tr>
    <th>Name</th>
    <th>Default value</th>
    <th>Description</th>
  </tr>
  <tr>
    <td>hostname</td>
    <td><pre>dashboard.{{ cluster_name }}</pre></td>
    <td>Address on which the Kubernetes Dashboard UI is located. Actually an alias for <pre>ingress.spec</pre></td>
  </tr>
  <tr>
    <td>dashboard.image</td>
    <td><pre>kubernetesui/dashboard:{{ plugins["kubernetes-dashboard"].version }}</pre></td>
    <td>Kubernetes Dashboard image.</td>
  </tr>
  <tr>
    <td>metrics-scraper.image</td>
    <td><pre>kubernetesui/metrics-scraper:{{ globals.compatibility_map.software["kubernetes-dashboard"][services.kubeadm.kubernetesVersion]["metrics-scraper-version"] }}</pre></td>
    <td>Kubernetes Dashboard Metrics Scraper image.</td>
  </tr>
  <tr>
    <td>ingress.metadata</td>
    <td><pre>name: kubernetes-dashboard
namespace: kubernetes-dashboard
annotations:
  nginx.ingress.kubernetes.io/backend-protocol: "HTTPS"
  </pre></td>
    <td>Ingress metadata, typically contains namespace and NGINX-specific parameters.</td>
  </tr>
  <tr>
    <td>ingress.spec</td>
    <td><pre>
        tls:
          - hosts:
            - '{{ plugins["kubernetes-dashboard"].hostname }}'
        rules:
          - host: '{{ plugins["kubernetes-dashboard"].hostname }}'
            http:
              paths:
                - path: /
                  pathType: Prefix
                  backend:
                    service:
                      name: kubernetes-dashboard
                      port:
                        number: 443
    </pre></td>
    <td>Ingress specs, determining where and on which port the Kubernetes Dashboard UI is located.</td>
  </tr>
</table>

If you do not want the default parameters, you can override them.

The following is an example to use custom dashboard address:

```yaml
plugins:
  kubernetes-dashboard:
    install: true
    hostname: 'mydashboard.k8s.example.com'
```

The following is an example to use custom dashboard images:

```yaml
plugins:
  kubernetes-dashboard:
    install: true
    dashboard:
      image: kubernetesui/dashboard:v2.4.0-rc2
    metrics-scraper:
      image: kubernetesui/metrics-scraper:v1.0.7
```

The following is an example to redefine ingress parameters:

```yaml
plugins:
  kubernetes-dashboard:
    install: true
    ingress:
      metadata:
        name: kubernetes-dashboard
        namespace: kubernetes-dashboard
        annotations:
          nginx.ingress.kubernetes.io/backend-protocol: "HTTPS"
          nginx.ingress.kubernetes.io/ssl-redirect: "true"
          nginx.ingress.kubernetes.io/rewrite-target: /
          nginx.ingress.kubernetes.io/secure-backends: "true"
          nginx.ingress.kubernetes.io/ssl-passthrough: "true"
      spec:
        tls:
          - hosts:
            - 'mydashboard.k8s.example.com'
        rules:
          - host: 'mydashboard.k8s.example.com'
            http:
              paths:
                - path: /
                  pathType: Prefix
                  backend:
                    service:
                      name: kubernetes-dashboard
                      port:
                        number: 443
```
 
**Warning**: Be very careful when overriding these parameters.

##### local-path-provisioner

Before proceeding, visit [official Local Path Provisioner repository](https://github.com/rancher/local-path-provisioner).

By default, the local path provisioner is not installed, as it is not a 
mandatory part of the cluster. However, you can install it by enabling the 
plugin.

The following is an example to enable this plugin:
```yaml
plugins:
  local-path-provisioner:
    install: true
```

If you enable the plugin, all other parameters are applied by default. The 
following is a list of supported parameters:

| Name | Default value | Description |
| :---: |:---:| --- |
| storage-class.name | `local-path` | Name of the storage class resource, which describes the class of the local volumes created by the provisioner. |
| storage-class.is-default | `"false"` | If `"true"`, the created storage class is the default one. |
| volume-dir | `/opt/local-path-provisioner` | The directory on each node, where the provisioner stores the PV data. For each requested PV, the provisioner creates the subdirectory in the volume-dir. |

If you do not want the default parameters, you can override them.

The following is an example to use custom volume directory:
```yaml
plugins:
  local-path-provisioner:
    install: true
    volume-dir: /mnt/local-path-provisioner-volume
```

The following is an example to create default storage class:
```yaml
plugins:
  local-path-provisioner:
    install: true
    storage-class:
      is-default: "true"
```

The following is an example to use custom provisioner and helper pod image:
```yaml
plugins:
  local-path-provisioner:
    install: true
    image: rancher/local-path-provisioner:v0.0.20
    helper-pod-image: busybox:latest
```

#### Plugins Features

This section provides information about the plugin features in detail.

##### plugin_defaults

In the `plugin_defaults` section, you can describe any parameters that are to be applied by default to each record in the [Plugins](#plugins) section. It works the same way as [node_defaults](#node_defaults).

For example:

```yaml
plugin_defaults:
  installation:
    registry: artifactory.example.com:5443
```

For detailed description of `registry` parameter, see [Installation without Internet Resources](#installation-without-internet-resources).

##### Plugins Reinstallation

You can reinstall the necessary plugins without cluster reinstallation, for example, if the plugin configuration is corrupted.
You can also change the configuration of any plugin on an already running cluster.
To do this, you need to start the execution of the plugin task `deploy.plugins` and set the following:
* Set the parameter `install: true` for plugins that need to be reinstalled
* Set the parameter `install: false` for those plugins that do not need to be reinstalled.

Starting the task leads to re-application of the plugin configurations in the Kubernetes, which allows you to reinstall, reset, reconfigure the plugin to the desired parameters without stopping the Kubernetes cluster and other plugins.

The following is an example in which Calico and NGINX Ingress Controller not assigned for reinstall, and the Kubernetes Dashboard is assigned for reinstall:

```yaml
plugins:
  calico:
    install: false
  nginx-ingress-controller:
    install: false
  kubernetes-dashboard:
    install: true
```

**Warning**: The plugin reinstallation behavior is intended, but is not necessarily by custom plugins. For detailed information on the procedure for reinstalling custom plugins, contact the respective provider.

##### Plugins Installation Order

Plugins are installed in a strict sequential order. The installation sequence is determined by the `installation.priority` parameter in each plugin separately. Predefined plugins have the following predefined installation priorities:

|Plugin|Priority|
|---|---|
|calico|`0`|
|nginx-ingress-controller|`1`|
|kubernetes-dashboard|`2`|
|local-path-provisioner|`2`|

You can change the priorities of preinstalled plugins, as well as set your own priority for the custom plugins.
The following is an example of how to prioritize a plugin:

```yaml
plugins:
  kubernetes-dashboard:
    install: true
    installation:
      priority: 55
```

After the priorities are set, you can see the sequence of installation in the stdout.

If you do not set the priorities for the plugins, they are installed in any order immediately after the plugins for which the priorities are set. Also, if the plugins have the same priority, they are installed in any order.

##### Node Selector

It is possible to set custom nodeSelectors for the OOB plugins in order to influence pods scheduling for particular plugin.

The following table contains details about existing nodeSelector configuration options:

<table>
    <tr><th>Plugin</th><th>YAML path (relative)</th><th>Default</th><th>Notes</th></tr>
    <tr>
        <td>calico</td>
        <td><ul>
            <li><code>typha.nodeSelector</code></li>
            <li><code>kube-controllers.nodeSelector</code></li>
            <li><code>apiserver.nodeSelector</code></li>
        </ul></td>
        <td><code>kubernetes.io/os: linux</code></td>
        <td>nodeSelector applicable only for calico <b>typha</b> <br>, calico <b>kube-controllers</b>, and calico <b>apiserver</b> containers, <br> but not for ordinary calico containers, <br> which should be deployed on all nodes</td>
    </tr>
    <tr>
        <td>nginx-ingress-controller</td>
        <td><code>controller.nodeSelector</code></td>
        <td>
            <code>kubernetes.io/os: linux</code><br>
        </td>
        <td></td>
    </tr>
    <tr>
        <td>kubernetes-dashboard</td>
        <td><ul>
            <li><code>dashboard.nodeSelector</code></li>
            <li><code>metrics-scraper.nodeSelector</code></li>
        </ul></td>
        <td><code>kubernetes.io/os: linux</code></td>
        <td></td>
    </tr>
</table>

For example, if you want to customize Calico kube-controllers pods to be scheduled only on nodes with `netcracker-infra: infra` label, you need to specify the following in your `cluster.yml` file:

```yaml
plugins:
  calico:
    kube-controllers:
      nodeSelector:
        netcracker-infra: infra
```

Custom nodeSelector is merged with default nodeSelector that results in the following configuration:

```yaml
plugins:
  calico:
    kube-controllers:
      nodeSelector:
        beta.kubernetes.io/os: linux
        netcracker-infra: infra
```

**Note**: You need to specify corresponding labels for nodes in order for `nodeSelector` customization to work.

##### Tolerations

It is possible to set custom tolerations for the provided OOB plugins in order to influence pods scheduling for particular plugin.

The following table contains details about existing tolerations configuration options:

<table>
    <tr><th>Plugin</th><th>YAML path (relative)</th><th>Default</th><th>Notes</th></tr>
    <tr>
        <td>calico</td>
        <td><ul>
            <li><code>typha.tolerations</code></li>
            <li><code>kube-controllers.tolerations</code></li>
            <li><code>apiserver.tolerations</code></li>
        </ul></td>
        <td>Delegates to default Calico tolerations except for extra <a href="#default-typha-tolerations">Default Typha Tolerations</a></td>
        <td>tolerations are not configurable for calico-node pods</td>
    </tr>
    <tr>
        <td>nginx-ingress-controller</td>
        <td><ul><li><code>controller.tolerations</code></li></ul></td>
        <td>none</td>
        <td></td>
    </tr>
    <tr>
        <td>kubernetes-dashboard</td>
        <td><ul>
            <li><code>dashboard.tolerations</code></li>
            <li><code>metrics-scraper.tolerations</code></li>
        </ul></td>
        <td>none</td>
        <td></td>
    </tr>
    <tr>
        <td>local-host-provisioner</td>
        <td><ul>
            <li><code>tolerations</code></li>
        </ul></td>
        <td>none</td>
        <td></td>
    </tr>
</table>

For example, if you want to customize the nginx-ingress-controller pods to allow scheduling on control-plane nodes, you need to specify the following tolerations in your `cluster.yml` file:

```yaml
plugins:
  nginx-ingress-controller:
    controller:
      tolerations:
        - key: node-role.kubernetes.io/control-plane
          operator: Exists
          effect: NoSchedule
```

##### Resources Requests and Limits

It is recommended to set resources requests and limits for plugins. 
There are default values, but you should adjust them accordingly to your needs. 

The following table contains details about existing resources requests and limits configuration options:

<table>
    <tr><th>Plugin</th><th>YAML path (relative)</th><th>Default requests/limits</th></tr>
    <tr>
        <td>calico</td>
        <td><ul>
            <li><code>node.resources</code></li>
            <li><code>typha.resources</code></li>
            <li><code>kube-controllers.resources</code></li>
            <li><code>apiserver.resources</code></li>
        </ul></td>
        <td><ul>
            <li><code>cpu=250m/None; memory=256Mi/None</code></li>
            <li><code>cpu=250m/None; memory=256Mi/None</code></li>
            <li><code>cpu=100m/None; memory=128Mi/None</code></li>
            <li><code>cpu=50m/100m; memory=100Mi/200Mi</code></li>
        </ul></td>
    </tr>
    <tr>
        <td>nginx-ingress-controller</td>
        <td><ul>
            <li><code>controller.resources</code></li>
            <li><code>webhook.resources</code></li>
        </ul></td>
        <td><ul>
            <li><code>cpu=100m/200m; memory=90Mi/256Mi</code></li>
            <li><code>cpu=10m/20m; memory=20Mi/40Mi</code></li>
        </ul></td>
    </tr>
    <tr>
        <td>kubernetes-dashboard</td>
        <td><ul>
            <li><code>dashboard.resources</code></li>
            <li><code>metrics-scraper.resources</code></li>
        </ul></td>
        <td><ul>
            <li><code>cpu=100m/1000m; memory=200Mi/200Mi</code></li>
            <li><code>cpu=50m/200m; memory=90Mi/200Mi</code></li>
        </ul></td>
    </tr>
    <tr>
        <td>local-host-provisioner</td>
        <td><ul>
            <li><code>resources</code></li>
        </ul></td>
        <td><ul>
            <li><code>cpu=100m/200m; memory=128Mi/256Mi</code></li>
        </ul></td>
    </tr>
</table>

For example, if you want to customize the nginx-ingress-controller resources requests and limits, 
you need to specify the following in your `cluster.yml` file:

```yaml
plugins:
  nginx-ingress-controller:
    controller:
      resources:
        requests:
          cpu: 100m
          memory: 90Mi
        limits:
          cpu: 200m
          memory: 256M
```

#### Custom Plugins Installation Procedures

During the installation of plugins, certain installation procedures are performed. You can use these procedures to write your custom plugins. The procedures should be presented as a list in the `installation.procedures` section in plugin definition, where each element is a separate procedure execution.
For example:

```yaml
plugins:
  example-plugin:
    installation:
      procedures:
        - shell: mkdir -p /var/data
        - template: /var/data/template.yaml.j2
        - config:
            source: /var/data/config.yaml
            do_render: False
        - expect:
            pods:
              - my-service
        - ansible: /var/data/playbook.yaml
        - python:
            module: /opt/checker/cluster.py
            method: check_service
            arguments:
              pod-name: my-service
```

The procedures are executed strictly one after another according to the procedure list. The procedures of the same type can be called multiple times.

A description of each type of plugins procedures is presented below.

**Note**: It is highly recommended to write plugin installation procedures so that they are idempotent and it should be possible to run the installation for the plugin several times and the result should be the same.
Consequent plugin installations should not perform re-installation of the plugin, they should ensure that the plugin is already installed.
For this reason, be cautious with `python`, `shell`, and `ansible` installation procedures.

##### template

This procedures allows you to automatically compile the Jinja2 template file, upload to remote hosts, and apply it. The following parameters are supported:

|Parameter|Mandatory|Default Value|Description|
|---|---|---|---|
|**source**|**yes**| |The local absolute path to the source Jinja2 template file. It is compiled before uploading to hosts.|
|**destination**|no|`/etc/kubernetes/{{ filename from source }}`|The absolute path on the hosts where the compiled template needs to be uploaded.|
|**apply_required**|no|`True`|A switch to call the command to apply the uploaded template on remote hosts.|
|**apply_command**|no|`kubectl apply -f {{ destination }}`|The command to apply the template on remote hosts after uploading it. It is called only if the switch `apply_required` is on.|
|**sudo**|no|`True`|A switch for the command execution from the sudoer.|
|**destination_groups**|no|`None`|List of groups on which the compiled template needs to be uploaded.|
|**destination_nodes**|no|`None`|List of nodes on which the compiled template needs to be uploaded.|
|**apply_groups**|no|`None`|List of groups on which the template apply command needs to be executed.|
|**apply_nodes**|no|`None`|List of nodes on which the template apply command needs to be executed.|

Inside the templates you can use all the variables defined in the inventory in `cluster.yaml`.
Moreover, it is possible to dynamically create your own variables in runtime using `python` or `shell` plugin procedures.
These runtime variables can also be used in templates by accessing `runtime_vars`, for example if you have variable
`example_var` created in runtime you can access this variable in templates like `runtime_vars['example_var']`

**Note**: You can specify nodes and groups at the same time.

**Note**: If no groups and nodes defined, by default control-plane group is used for destination and the first control-plane node is used for applying.

**Note**: You can use wildcard source. For example: 
`/tmp/my_templates/*.yaml`. This source argument matches every `.yaml` template in the `my_templates` directory.

The following is an example of using all parameters at a time:

```yaml
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

The following is an example of applying a Kubernetes configuration:

```yaml
plugins:
  nginx-ingress-controller:
    installation:
      procedures:
        - template:
            source: /var/data/plugins/nginx-ingress-controller.yaml.j2
```

The following is an example of applying configuration with custom ctl:

```yaml
plugins:
  calico:
    installation:
      procedures:
        - template:
            source: /var/data/plugins/calico-ippool.yaml.j2
            destination: /etc/calico/ippool.yaml
            apply_command: 'calicoctl apply -f /etc/calico/ippool.yaml'
```

The following is an example of uploading a compiled Jinja2 template to control-planes and workers without applying it:

```yaml
plugins:
  calico:
    installation:
      procedures:
        - template:
            source: /var/data/plugins/calicoctl.cfg.j2
            destination: /etc/calico/calicoctl.cfg
            destination_groups: ['control-plane', 'worker']
            apply_required: false
```

A short format of template procedure is available. In this format only mandatory source paths should be specified. For example:

```yaml
plugins:
  example-plugin:
    installation:
      procedures:
        - template: /var/data/template.yaml.j2
```

It equals to the following record:

```yaml
plugins:
  example-plugin:
    installation:
      procedures:
        - template:
            source: /var/data/template.yaml.j2
```

##### config

This procedure is an alias for [template](#template) that allows you not to render the contents of the files by using an additional property, `do_render`. By default, this value is defined as `True`, which specifies that the content is rendered as in the `Template` procedure. 

All the parameters match with [template](#template).

|Parameter|Mandatory|Default Value|Description|
|---|---|---|---|
|**do_render**|**no**|**True**| Allows you not to render the contents of the file.|

**Note**: If `do_render: false` is specified, Kubemarine uploads the file without any transformation.
It is desirable for such files to have LF line endings.
This is especially relevant for Windows deployers
and is important if the files are aimed for services that are sensitive to line endings.

##### expect pods

This procedure allows you to wait until the necessary pods are ready. You have to declare a procedure section and specify the list of the pod names that should be expected.
For example:

```yaml
plugins:
  calico:
    installation:
      procedures:
        - expect:
            pods:
              - coredns
              - calico-kube-controllers
              - calico-node
```

**Note**: You can specify some part of the pod name instead of the full name of the container.

The procedure tries once every few seconds to find the necessary pods and detect their running status. If you use the standard format of this procedure, then pods are expected in accordance with the following configurations:

|Configuration|Value|Description|
|---|---|---|
|timeout|`5`|The number of seconds until the next pod status check.|
|retries|`45`|The number of attempts to check the status.|

The total waiting time is calculated by multiplying the configuration `timeout * retries`, for default values it is 2 to 5 minutes to wait.
If during this time, the pods do not have a ready status, then a corresponding error is thrown and the work is stopped.
Also, if at least one of the expected pods is detected in the status of a fail, an error is thrown without waiting for the end of the total waiting time.
If you are not satisfied with the default wait values, you can use the advanced form of the procedure record. For example:

```yaml
plugins:
  calico:
    installation:
      procedures:
        - expect:
            pods:
              timeout: 10
              retries: 60
              list:
                - coredns
                - calico-kube-controllers
                - calico-node
```

Default values for plugins pods expect timeout and retries are:

|Configuration|Value|Description|
|---|---|---|
|timeout|`5`|The number of seconds until the next pod status check.|
|retries|`150`|The number of attempts to check the status.|

These values can be changed in a particular `expect` or globally:

```
globals:
  expect:
    pods:
      plugins:
        timeout: 10
        retries: 25
```

##### expect deployments/daemonsets/replicasets/statefulsets

This procedure is similar to `expect pods`, but it is intended to wait for deployments/daemonsets/replicasets/statefulsets. For example:

```
plugins:
  calico:
    installation:
      procedures:
        - expect:
            daemonsets:
              - calico-node
            deployments:
              - calico-kube-controllers

```

**Note**: You can specify some part of the resource name instead of its full name.

The procedure tries once every few seconds to find the necessary resources and detect their status. If you use the standard format of this procedure, then the resources are expected in accordance with the following configurations:

|Configuration|Value|Description|
|---|---|---|
|timeout|`5`|The number of seconds until the next resource status check.|
|retries|`30`|The number of attempts to check the status.|

The total waiting time in seconds is calculated by multiplying the configuration `timeout * retries`.
If during this time, the resources do not have an up-to-date status, then a corresponding error is thrown and the work is stopped.
If you are not satisfied with the default wait values, you can use the advanced form of the procedure record. For example:

```
plugins:
  calico:
    installation:
      procedures:
        - expect:
            daemonsets:
              list:
               - calico-node
              timeout: 10
              retries: 100
            deployments:
              list:
               - calico-kube-controllers
               retries: 60

```

Default values for deployments/daemonsets/replicasets/statefulsets expect timeout and retries are:

|Configuration|Value|Description|
|---|---|---|
|timeout|`5`|The number of seconds until the next status check.|
|retries|`45`|The number of attempts to check the status.|

These values can be changed in a particular `expect` or globally:

```
globals:
  expect:
    deployments:
      timeout: 10
      retries: 15
```


##### python

This procedure allows you to directly call the Python 3 code.
This is helpful when you want to connect a ready-made product in Python, or for example you have complex business logic that can only be described in a programming language.
For this procedure, you must specify the following parameters:

|Parameter|Description|
|---|---|
|**module**|The absolute path on local host to the Python 3 module to be loaded.|
|**method**|The name of the method to call.|
|**arguments**|Optional. Key-value map, which should be applied as kwargs to the requested method.|

**Note**: The python code is executed on the deploying node and not on remote nodes.

**Note**: The called method **must** accept a cluster object as the first argument.

For example:

```yaml
plugins:
  nginx-ingress-controller:
    installation:
      procedures:
        - python:
            module: plugins/builtin.py
            method: apply_yaml
            arguments:
              plugin_name: nginx-ingress-controller
              original_yaml_path: plugins/yaml/nginx-ingress-controller-{{ plugins.nginx-ingress-controller.version }}-original.yaml
```

##### thirdparty

This procedure allows you to trigger specific thirdparty installation. This thirdparty must be configured in the [thirdparties](#thirdparties) section and its destination path must be specified in this procedure. In this case, thirdparty is not installed in `prepare.thirdparties` task, but is installed during the installation of the current plugin.
For example:

```yaml
services:
  thirdparties:
    /usr/bin/calicoctl:
      source: 'https://example.com/calico/calicoctl-linux-amd64'
plugins:
  calico:
    installation:
      procedures:
        - thirdparty: /usr/bin/calicoctl
```

##### shell

This procedure allows you to execute shell code on remote hosts. The following parameters are supported:

|Parameter|Mandatory|Default Value|Description|
|---|---|---|---|
|**command**|**yes**| |A shell command to be executed on remote hosts.|
|**sudo**|no|`False`|Switch for the command execution from the sudoer.|
|**groups**|no|`None`|List of groups on which the shell command should be executed.|
|**nodes**|no|`None`|List of nodes on which the shell command should be executed.|
|**out_vars**|no|`None`|List of ENV variables to export and save for later use|
|**in_vars**|no|`None`|List of ENV variables to import before command execution|

**Note**: You can specify nodes and groups at the same time.

**Note**: If no groups or nodes are specified, then by default the first control-plane is used.

For example:

```yaml
plugins:
  calico:
    installation:
      procedures:
        - shell:
            command: mkdir -p /etc/calico
            groups: ['control-plane']
            sudo: true
```

There is support for a shortened format. In this case, you need to specify only the command to execute, all other parameters are set by default. For example:

```yaml
plugins:
  calico:
    installation:
      procedures:
        - shell: whoami
```

It equals to the following record:

```yaml
plugins:
  example-plugin:
    installation:
      procedures:
        - shell:
            command: whoami
```

If you combine several commands, for example `whoami && whoami` with `sudo: true`, the second command is executed from non-sudoer. In this case, specify `sudo` for second command explicitly. For example:

```yaml
plugins:
  example-plugin:
    installation:
      procedures:
        - shell:
            command: whoami && sudo whoami
            sudo: true
```

Also try to avoid complex shell features, for example pipe redirection. Shell procedure is only for simple command invocation, but not for complex shell scripts. If you need to call complex shell logic, place a script file, upload it to a remote host, and call the script. For example:

```yaml
plugins:
  calico:
    installation:
      procedures:
        - config:
            source: /var/data/plugins/script.sh
            destination: /etc/calico/script.sh
            destination_nodes: ['control-plane-1']
            apply_required: false
            do_render: false
        - shell:
            command: bash -x /etc/calico/script.sh
            nodes: ['control-plane-1']
            sudo: true
```

For more information, see the [config](#config) procedure type.

Example of runtime variables usage in shell procedure:

```yaml
plugins:
  example-plugin:
    installation:
      procedures:
        - shell:
            command: 
              - echo $input_var $input_var_1
              - export output_var='this string will be saved to `runtime_vars` with name `output_var`'
              - export output_var_2='this string will be saved to `runtime_vars` with name `example_var_alias`'
            out_vars:
              - name: output_var
              - name: output_var_2
                save_as: example_var_alias
            in_vars:
              - name: input_var # value for this var should be set in runtime as it is for `output_var`, or else it will be empty
              - name: input_var_1
                value: static value, which can also be rendered {{ like_this }}
```

##### ansible

This procedure allows you to directly execute Ansible playbooks. This is useful when you have a ready-made set of playbooks required for your business logic and you need to execute them during the installation process.
For this procedure you must specify the following parameters:

|Parameter|Mandatory|Default Value|Description|
|---|---|---|---|
|**playbook**|**yes**| |An absolute path for playbook to be executed.|
|**vars**|no|`None`|Additional variables, overriding variables from Ansible inventory. They are passed as `--extra-vars` in CLI.|
|**become**|no|`False`|Privilege escalation switch. Enables `-b` argument.|
|**groups**|no|`None`|Targeted list of groups, passed to Ansible as `--limit` argument.|
|**nodes**|no|`None`|Targeted list of nodes, passed to Ansible as `--limit` argument.|

**Note**: The playbook execution starts on the deploying node, not on remote nodes.

**Note**: Ansible must be manually installed on the deploying node.

**Note**: Executing of the playbooks is currently not supported on Windows deployers.

**Note**: An [Ansible Inventory](#ansible-inventory) is provided to the playbook, so it should not be disabled.

**Note**: When calling ansible plugin from Kubemarine container, note that Kubemarine container is shipped with `ansible-2.9.*`.
Exact patch version is not fixed.

For example:

```yaml
plugins:
  example-plugin:
    installation:
      procedures:
        - ansible:
            playbook: /var/data/plugins/playbook.yaml
            vars:
              foo: bar
            become: True
            groups: ['control-plane', 'worker']
```

There is support for a shortened format. In this case, you need to specify only path to the playbook, all other parameters are set by default. For example:

```yaml
plugins:
  calico:
    installation:
      procedures:
        - ansible: /var/data/plugins/playbook.yaml
```

It equals to the following record:

```yaml
plugins:
  example-plugin:
    installation:
      procedures:
        - ansible:
            playbook: /var/data/plugins/playbook.yaml
```

##### helm

You can install or upgrade HELM chart on Kubernetes cluster.
If a Helm chart is already installed on the cluster, the `helm upgrade` command is called, otherwise `helm install` command is called.

Specify the following parameters:

The `chart_path` parameter specifies the absolute path on local host to the Helm chart. The URL link to chart archive is also supported.

The `values_file` parameter specifies the absolute path on the local host to the file with YAML formatted values for the chart that override values from the `values.yaml` file from the provided chart.
This parameter is optional.

The `values` parameter specifies the YAML formatted values for the chart that override values from the `values.yaml` file from the provided chart.
The values from this parameter also override the values from the `values_file` parameter.
This parameter is optional.

The `namespace` parameter specifies the cloud namespace where chart should be installed. This parameter is optional.

The `release` parameter specifies target Helm release. The parameter is optional and is equal to chart name by default.

**Note**:

* Helm 3 is only supported.

For example:

```yaml
plugins:
  some_plugin: 
    install: True   
    installation:
      priority: 10
      procedures:
        - helm:
            chart_path: /tmp/some-chart
            values:
              serviceAccount:
                create: false
            namespace: elastic-search
            release: elastic-search-1
            values_file: /tmp/custom_values.yaml
```
 
## Advanced Features

Before use, the configuration file **cluster.yaml** is preprocessed. The user settings are merged with default settings, thereby creating the final configuration file, which
is further used throughout the entire installation.

**Note**: If [Dump Files](#dump-files) is enabled, then you can see merged **cluster.yaml** file version in the dump directory.

To simplify maintenance of the configuration file, the following advanced functionality appears in the yaml file:

* List merge strategy
* Dynamic variables
* Environment Variables

### List Merge Strategy

It is possible to define the following strategies when merging two lists:

* **replace** - It indicates that the contents of one list must be replaced by
  other. This strategy is useful when you need to completely replace the default
  list with the settings on your own. If no strategy is specified, then this
  strategy is applied by default.
* **merge** - It indicates that the contents of one list must be merged with
  other. This strategy is useful when you need to merge the default list of
  settings with your list, without replacing the earlier list.

To define a strategy in the list, you must specify a new list element. In
this element, you need to put a key-value pair, where the key is `<<`, and value
is the name of the join strategy.

**Note**: This functionality is available only for lists and only a single strategy pointer is allowed inside the list.

**Note**: This functionality is available only in specific sections of the inventory file.
For a detailed set of allowed sections, refer to [List Merge Allowed Sections](#list-merge-allowed-sections).

The following is an example of `replace` strategy:

```yaml
plugins:
  calico:
    installation:
      procedures:
        - template: /var/data/custom_template.yaml.j2
        - '<<': replace
```

The user list replaces the default:

```yaml
plugins:
  calico:
    installation:
      procedures:
        - template: /var/data/custom_template.yaml.j2
```

The following is an example of `merge` strategy:

```yaml
plugins:
  calico:
    installation:
      procedures:
        - template: /var/data/custom_template.yaml.j2
        - '<<': merge
```

The result is as follows:

```yaml
plugins:
  calico:
    installation:
      procedures:
        - template: /var/data/custom_template.yaml.j2
        - template: templates/plugins/calico.yaml.j2
          expect:
            pods:
              - coredns
```

#### Merge Strategy Positioning

With the `merge` strategy, you can specify a specific place for the content
from the default list inside the user list.

For example, you can indicate it at the beginning:

```yaml
plugins:
  calico:
    installation:
      procedures:
        - '<<': merge
        - template: /var/data/custom_template.yaml.j2
        - template: /var/data/custom_template2.yaml.j2
```

As a result, the default part of the list is at the beginning, and the user
part at the end:

```yaml
plugins:
  calico:
    installation:
      procedures:
        - template: templates/plugins/calico.yaml.j2
          expect:
            pods:
              - coredns
        - template: /var/data/custom_template.yaml.j2
        - template: /var/data/custom_template2.yaml.j2
```

You can specify it at the end as follows:

```yaml
plugins:
  calico:
    installation:
      procedures:
        - template: /var/data/custom_template.yaml.j2
        - template: /var/data/custom_template2.yaml.j2
        - '<<': merge
```

As a result, the default part of the list is at the end, and the user part at the beginning:

```yaml
plugins:
  calico:
    installation:
      procedures:
        - template: /var/data/custom_template.yaml.j2
        - template: /var/data/custom_template2.yaml.j2
        - template: templates/plugins/calico.yaml.j2
          expect:
            pods:
              - coredns
```

You can specify in the middle as follows:

```yaml
plugins:
  calico:
    installation:
      procedures:
        - template: /var/data/custom_template.yaml.j2
        - '<<': merge
        - template: /var/data/custom_template2.yaml.j2
```

The result is as follows:

```yaml
plugins:
  calico:
    installation:
      procedures:
        - template: /var/data/custom_template.yaml.j2
        - template: templates/plugins/calico.yaml.j2
          expect:
            pods:
              - coredns
        - template: /var/data/custom_template2.yaml.j2
```

#### List Merge Allowed Sections

Application of the list merge strategy is allowed in the following sections:
* `plugins.installation.procedures`
* `services.kubeadm.apiServer.extraVolumes`
* `services.kernel_security.permissive`
* `services.modprobe`
* `services.etc_hosts`
* `services.audit.cluster_policy.omitStages`
* `services.audit.cluster_policy.rules`
* `services.audit.rules`
* `services.coredns.deployment.spec.template.spec.volumes`
* `services.packages.install`
* `services.packages.upgrade`
* `services.packages.remove`
* `plugins.nginx-ingress-controller.ports`
* `plugins.kubernetes-dashboard.ingress.spec.tls`
* `plugins.kubernetes-dashboard.ingress.spec.rules`
* `rbac.pss.exemptions.usernames`
* `rbac.pss.exemptions.runtimeClasses`
* `rbac.pss.exemptions.namespaces`

### Dynamic Variables

There are settings in the configuration file that borrow their contents from the settings of the other sections. To avoid any duplication of the settings, the mechanism of dynamic variables is used.

This mechanism allows you to specify a link to one variable to another.

For example, the following parameters:

```yaml
section_one:
  variable: "test"
section_two:
  variable: '{{ section_one.variable }}'
```

This leads to the following result:

```yaml
section_one:
  variable: test
section_two:
  variable: test
```

Dynamic variables allow you to refer to the other variables, but can also be full-fledged Jinja2 templates.

For example, the following configuration:

```yaml
section_one:
section_two:
  variable: '{{ section_one.variable | default("nothing") }}'
```

This leads to the following result:

```yaml
section_one: null
section_two:
  variable: nothing
```

Recursive pointing to each other is also supported. For example:

```yaml
section:
  - variable: '{{ section[1].variable }}-2'
  - variable: '{{ section[2].variable }}-1'
  - variable: "hello"
```

The above configuration generates the following result:

```yaml
section:
- variable: hello-1-2
- variable: hello-1
- variable: hello
```

#### Limitations

Dynamic variables have some limitations that should be considered when working with them:

* Dynamic variables are not supported in inventory files of maintenance procedures like upgrade.
* All variables should be either valid variables that Kubemarine understands,
  or custom variables defined in the dedicated `values` section.
  ```yaml
  values:
    custom_variable: value
  kubemarine_section:
    kubemarine_variable: '{{ values.custom_variable }}'
  ```
* The start pointer of the Jinja2 template must be inside a pair of single or double quotes. The `{{` or `{%` out of quotes leads to a parsing error of the yaml file.
* The variable cannot refer to itself. It does not lead to any result, but it slows down the compilation process.
* The variables cannot mutually refer to each other. For example, the following configuration:

  ```yaml
  section:
   variable_one: '{{ section.variable_two }}'
   variable_two: '{{ section.variable_one }}'
  ```
  
  This leads to the following result:
   
  ```yaml
  section:
   variable_one: '{{ section.variable_one }}'
   variable_two: '{{ section.variable_one }}'
  ```
  The variables copy each other, but since none of them lead to any result, there is a cyclic link to one of them.

#### Jinja2 Expressions Escaping

Inventory strings can have strings containing characters that Jinja2 considers as their expressions. For example, if you specify a golang template. To avoid rendering errors for such expressions, it is possible to wrap them in exceptions `{% raw %}``{% endraw %}`. 
For example:

```yaml
authority: '{% raw %}{{ .Name }}{% endraw %} 3600 IN SOA'
```

### Environment Variables

Kubemarine supports environment variables inside the following places:
* The configuration file **cluster.yaml**.
* Jinja2 template files for plugins. For more information, refer to [template](#template).

Environment variables are available through the predefined `env` Jinja2 variable.
Refer to them inside the configuration file in the following way:

```yaml
section:
  variable: '{{ env.ENV_VARIABLE_NAME }}'
```

Environment variables inherit all features and limitations of the [Dynamic Variables](#dynamic-variables) including but not limited to:
* The ability to participate in full-fledged Jinja2 templates.
* The recursive pointing to other variables pointing to environment variables.

Consider the following more complex example:

```yaml
values:
  variable: '{{ env["ENV_VARIABLE_NAME"] | default("nothing") }}'

plugins:
  my_plugin:
    variable: '{{ values.variable }}'
```

The above configuration generates the following result, provided that `ENV_VARIABLE_NAME=ENV_VARIABLE_VALUE` is defined:

```yaml
values:
  variable: ENV_VARIABLE_VALUE

plugins:
  my_plugin:
    variable: ENV_VARIABLE_VALUE
```

## Installation without Internet Resources

If you want to install Kubernetes in a private environment, without access to the internet, then you need to redefine the addresses of remote resources.
Be careful with the following parameters:

|Path|Registry Type|Format|Example|Description|
|---|---|---|---|---|
|`services.kubeadm.imageRepository`|Docker|Address without protocol, where Kubernetes images are stored. It should be the full path to the repository.|```example.com:5443/registry.k8s.io```|Kubernetes Image Repository. The system container's images such as `kubeapi` or `etcd` is loaded from this registry.|
|`services.docker.insecure-registries`|Docker|List with addresses without protocol.|```example.com:5443```|Docker Insecure Registries. It is necessary for the Docker to allow connection to addresses unknown to it.|
|`services.docker.registry-mirrors`|Docker|List with addresses. Each address should contain a protocol.|```https://example.com:5443```|Docker Registry Mirrors. Additional image sources for container's images pull.|
|`services.thirdparties.{{ thirdparty }}.source`|Plain|Address with protocol or absolute path on deploy node. It should be the full path to the file.|```https://example.com/kubeadm/v1.16.3/bin/linux/amd64/kubeadm```|Thridparty Source. Thirdparty file, such as binary, archive and so on, is loaded from this registry.|
|`plugin_defaults.installation.registry`|Docker|Address without protocol, where plugins images are stored.|```example.com:5443```|Plugins Images Registry. All plugins container's images are loaded from this registry.|


# Installation Procedure

The installation information for Kubemarine is specified below.

**Warning**: Running the installation on an already running cluster redeploys the cluster from scratch.

## Installation Tasks Description

The following is the installation tasks tree:

* **prepare**
  * **check**
    * **sudoer** - Validates if the connection user has the sudoer permissions.
    * **system** - Validates the distributive and version of the hosts operating system.
    * **cluster_installation** - Looks for an already installed cluster.
  * **dns**
    * **hostname** - Configures nodes hostnames. 
    * **resolv_conf** - Configures the records in `/etc/resolv.conf` (backup is presented). For more information about parameters for this task, see [resolv.conf](#resolvconf). If no parameters are presented, the task is skipped.
    * **etc_hosts** - Configures the records in `/etc/hosts` (backup is presented). This task writes the node names and their addresses to this file.
  * **package_manager**
    * **configure** - Configures repositories for the package manager (backup is presented) and updates the repodata. For more information about parameters for this task, see [package_manager](#package_manager). If no parameters are presented, the task is skipped. OS-specific.
    * **manage_packages** - Manages packages on hosts. For more information about parameters for this task, see [packages](#packages). If no parameters are presented, the task is skipped. OS-specific.
  * **ntp**
    * **chrony** - Configures the file `/etc/chrony.conf` (backup is presented) and synchronizes the time using the `chronyd` service. For more information about parameters for this task, see [chrony](#chrony). If no parameters are presented or non-RHEL OS is used, the task is skipped.
    * **timesyncd** - Configures the file `/etc/systemd/timesyncd.conf` (backup is presented) and synchronizes the time using the `timesyncd` service. For more information about parameters for this task, see [timesyncd](#timesyncd). If no parameters are presented or non-Debian OS is used, the task is skipped.
  * **system**
    * **setup_selinux** - Configures SELinux. For more information about parameters for this task, see [SELinux](#selinux). The task is performed only for the RHEL OS family.
    * **setup_apparmor** - Configures AppArmor. For more information about parameters for this task, see [AppArmor](#apparmor). The task is performed only for the Debian OS family.
    * **disable_firewalld** - Forcibly disables FirewallD service.
    * **disable_swap** - Forcibly disables swap in system.
    * **modprobe** - Configures Linux Kernel modules. For more information about parameters for this task, see [modprobe](#modprobe).
    * **sysctl** - Configures Linux Kernel parameters. For more information about parameters for this task, see [sysctl](#sysctl).
    * **audit**
      * **install** - Installs auditd daemon on nodes.
      * **configure** - Configures Linux audit rules. For more information about parameters for this task, see [audit-daemon](#audit-daemon).

  * **cri**
    * **install** - Installs the container runtime. For more information about parameters for this task, see [CRI](#cri).
    * **configure** - Configures the container runtime. For more information about parameters for this task, see [CRI](#cri).
  * **thirdparties** - Downloads thirdparties and installs them. For more information about parameters for this task, see [thirdparties](#thirdparties).
* **deploy**
  * **loadbalancer**
    * **haproxy**
      * **install** - Installs HAProxy if balancers are presented in the inventory. If the HAProxy is already installed, then there is no reinstallation.
      * **configure** - Configures HAProxy in the file `/etc/haproxy/haproxy.cfg` (backup is presented).
    * **keepalived**
      * **install** - Installs Keepalived if `vrrp_ip` is presented in the inventory. If the Keepalived is already installed, then there is no reinstallation.
      * **configure** - Configures Keepalived in the file `/etc/keepalived/keepalived.conf` (backup is presented). For more information about parameters for this task, see [vrrp_ips](#vrrp_ips).
  * **kubernetes**
    * **reset** - Resets an existing or previous Kubernetes cluster. All the data related to the Kubernetes is removed, including the container runtime being cleaned up.
    * **install** - Configures Kubernetes service in the file `/etc/systemd/system/kubelet.service`
    * **prepull_images** - Prepulls Kubernetes images on all nodes using parameters from the inventory.
    * **init** - Initializes Kubernetes nodes via kubeadm with config files: `/etc/kubernetes/init-config.yaml` and `/etc/kubernetes/join-config.yaml`. For more information about parameters for this task, see [kubeadm](#kubeadm). Also apply PSS if it is enabled. For more information about PPS, see [Admission pss](#admission-pss).
    * **audit** - Configures Kubernetes audit rules. For more information about parameters for this task, see [audit-Kubernetes Policy](#audit-Kubernetes-Policy).
  * **admission** - Applies OOB and custom pod security policies. For more information about the parameters for this task, see [Admission psp](#admission-psp).
  * **coredns** - Configures CoreDNS service with [coredns](#coredns) inventory settings.
  * **plugins** - Applies plugin installation procedures. For more information about parameters for this task, see [Plugins](#plugins).
  * **accounts** - Creates new users in cluster. For more information about parameters for this task, see [RBAC accounts](#rbac-accounts).
* **overview** - Collects general information about the cluster and displays it in stdout.

**Note**: The task execution is strictly performed in the order as in the tree above.

## Installation of Kubernetes using CLI

Full installation using CLI can be started with the following command:

```bash
kubemarine install
```

It begins the execution of all tasks available in the installer in accordance with its task tree.

**Note**: The SSH-keyfile path in the config-file should be absolute, not relative.

### Custom Inventory File Location

If you are installing via CLI, you can specify the custom `cluster.yaml` location as follows:

```bash
kubemarine install --config="${PATH_TO_CONFIG}/cluster.yaml"
```

or shorter

```bash
kubemarine install -c "${PATH_TO_CONFIG}/cluster.yaml"
```

where, `${PATH_TO_CONFIG}` - is the path to the local inventory file.

**Note**: Use the absolute path in arguments, instead of relative.

# Installation Features

This section describes the installation features.

## Tasks List Redefinition

It is possible to override the default installation tasks tree with `--tasks` argument when installing via CLI, and as the contents list tasks names separated by commas.

The following is an example for CLI:

```bash
kubemarine install --tasks="prepare.dns.etc_hosts,deploy"
```

For detailed tree of tasks, see [Installation Tasks Description](#installation-tasks-description).

If required, you can exclude some tasks from the execution in `--exclude` argument when installing via CLI. The principle of action is the opposite of `tasks` argument/parameter.

Example:

```bash
kubemarine install --exclude="deploy.loadbalancer,deploy.kubernetes.install"
```

The arguments can be combined. For example, when you only need to perform a deploy, but not touch the balancers.

Example:

```bash
kubemarine install --tasks="deploy" --exclude="deploy.loadbalancer"
```

When you specify the name of the task, you can specify the following types:

* **group** - Logically separated part of the execution tree, which includes a
  certain set of tasks. For example, when you specify `prepare.dns` group, it
  executes only tasks from group: `prepare.dns.resolv_conf` and
  `prepare.dns.etc_hosts`, tasks from other groups are skipped.
* **task** - The exact address of the task to be performed. Others are skipped.

You can also combine the types, specify both groups and tasks at the same time. For example:

```bash
kubemarine install --tasks="prepare.system,prepare.dns.resolv_conf"
```

The Flow Filter filters everything and make a new execution tree, on which the
installation begins. The list of excluded tasks gets printed before
starting the work and displays as follows:

```
Excluded tasks:
	prepare
	deploy.loadbalancer
	deploy.plugins
	deploy.accounts
```

If nothing is excluded, it displays:

```
Excluded tasks:
	No excluded tasks
```

The Flow Filter also takes care of sorting the sequence of tasks. Therefore, you do
not need to consider the sequence for listing the tasks. You can do it in any sequence, and then the actual sequence of the tasks is automatically decided and followed at the time of installation.

**Note**: The sequence cannot be changed, it is hardcoded into the source code. This is done intentionally since some tasks are dependent on others.

## Logging

Kubemarine has the ability to customize the output of logs, as well as customize the output to a separate file or graylog.
For more information, refer to the [Configuring Kubemarine Logging](Logging.md) section.

## Dump Files

During installation configurations, templates and other files are generated. For best user experience, these configurations are not displayed in the output log.
However, by default, all intermediate results are saved in the dump directory, which is automatically created at the beginning of work.
It is not recommended but you can also disable this functionality.

The dumped files are put into the `dump` directory which is located by default in the executable directory. However, you can put the `dump` directory into any other folder instead of the executable directory using the `--dump-location` argument. For example:

```
$ install --dump-location /var/data/
```

**Note**: When creating a dump directory, the entire hierarchy of directories is created recursively in accordance with the specified path, even if a part of the path is missing.

You can use the `--disable-dump` argument to disable the dumping feature that disables creation of the dump directory and stop storing dump files in it.
The following example turns off the dump:

```
$ install --disable-dump
```

If you want a dump to be created, but you do not want it to be cleaned every time, you can turn off the automatic cleaning using the `disable-dump-cleanup` parameter. For example:

```
$ install --disable-dump-cleanup
```

### Finalized Dump

After any procedure is completed, a final inventory with all the missing variable values is needed, which is pulled from the finished cluster environment.
This inventory can be found in the `cluster_finalized.yaml` file in the working directory,
and can be passed as a source inventory in future runs of Kubemarine procedures.

**Note**: The `cluster_finalized.yaml` inventory file is aimed to reflect the current cluster state together with the Kubemarine version using which it is created.
This in particular means that the file cannot be directly used with a different Kubemarine version.
Though, it still can be migrated together with the managed cluster using the [Kubemarine Migration Procedure](/documentation/Maintenance.md#kubemarine-migration-procedure).

In the file, you can see not only the compiled inventory, but also some converted values depending on what is installed on the cluster.
For example, consider the following package's origin configuration:

```yaml
services:
  packages:
    associations:
      docker:
        executable_name: 'docker'
        package_name:
          - docker-ce-19.03*
          - docker-ce-cli-19.03*
          - containerd.io-1.4.6*
        service_name: 'docker'
        config_location: '/etc/docker/daemon.json'
      conntrack:
        package_name: conntrack-tools
    install:
      - ethtool
      - ebtables
      - socat
```

The above configuration is converted to the following finalized configuration, provided that the cluster is based on RHEL nodes:

```yaml
services:
  packages:
    associations:
      rhel:
        docker:
          executable_name: 'docker'
          package_name:
            - docker-ce-19.03.15-3.el7.x86_64
            - docker-ce-cli-19.03.15-3.el7.x86_64
            - containerd.io-1.4.6-3.1.el7.x86_64
          service_name: 'docker'
          config_location: '/etc/docker/daemon.json'
        conntrack:
          package_name: conntrack-tools-1.4.4-7.el7.x86_64
    install:
      include:
        - ethtool-4.8-10.el7.x86_64
        - ebtables-2.0.10-16.el7.x86_64
        - socat-1.7.3.2-2.el7.x86_64
```

**Note**: Some of the packages are impossible to be detected in the system, therefore such packages remain unchanged.
The same rule is applied if two different package versions are detected on different nodes.
Also, see the `cache_versions` option in the [associations](#associations) section.

**Note**: After some time is passed, the detected package versions might disappear from the repository.
Direct using of the `cluster_finalized.yaml` file in procedures like `install` or `add_node` might be impossible due to this reason, and would require a manual intervention.

The same applies to the VRRP interfaces. For example, the following origin configuration without interfaces:

```yaml
vrrp_ips:
  - ip: 192.168.101.1
    floating_ip: 1.101.10.110
```

The above configuration is converted to the following configuration with real interfaces as it is presented on the keepalived nodes:

```yaml
vrrp_ips:
- floating_ip: 1.101.10.110
  hosts:
  - interface: eth0
    name: balancer-1
  - interface: eth0
    name: balancer-2
  ip: 192.168.101.1
```

**Note**: Also, finalization escapes the golang expression; this required for prevention incompatibility with the jinja parser.


## Configurations Backup

During perform of Kubemarine, all configuration files on the nodes are copied to their backup copies before being overwritten. Also, all versions of the file, that are different from each other, are saved, and new copies are incremented in the file name. This protects from losing important versions of configuration files and allows to restore the desired file from a necessary backup version. After several installations, you can find the file and all its backups as in the following example:

```bash
$ ls -la /etc/resolv.conf*
-rw-rw-r--. 1 root root  78 jul  5 08:57 /etc/resolv.conf
-rw-r--r--. 1 root root 117 jul  5 08:55 /etc/resolv.conf.bak1
-rw-r--r--. 1 root root 216 jul  5 08:57 /etc/resolv.conf.bak2
```


## Ansible Inventory

By default, during installation a new Ansible inventory file is converted from **cluster.yaml** file.
Ansible inventory file is available in the root directory of the distribution immediately after starting the installation.

If you want to generate only an inventory file, you must run the installer with the argument `--without-act`. For example:

```bash
kubemarine install --without-act
```

You can specify custom path and name for the ansible inventory file, using the argument `--ansible-inventory-location`. By default, the file is saved to the executable directory with the name `ansible-inventory.ini`. For example:

```bash
kubemarine install --ansible-inventory-location /var/data/ansible-inventory.ini
```

**Warning**: Always specify the absolute path to the file, not relative.

Arguments can be combined. For example the following arguments generate the inventory without starting the installation:

```bash
kubemarine install --without-act --ansible-inventory-location /var/data/inventory.ini
```

### Contents

The automatically converted information is placed in the inventory file, divided into the following sections.

#### [all]

The `[all]` section contains the following basic knowledge about nodes to connect to:
* Node name
* Ansible-host
* Internal IP address
* External IP address (if exists)

For example:

```ini
[all]
localhost ansible_connection=local
k8s-lb ansible_host=10.101.10.1 ip=192.168.0.1 external_ip=10.101.10.1
k8s-control-plane-1 ansible_host=10.101.10.2 ip=192.168.0.2 external_ip=10.101.10.2
k8s-control-plane-2 ansible_host=10.101.10.3 ip=192.168.0.3 external_ip=10.101.10.3
k8s-control-plane-3 ansible_host=10.101.10.4 ip=192.168.0.4 external_ip=10.101.10.4
k8s-worker-1 ansible_host=10.101.10.5 ip=192.168.0.5 external_ip=10.101.10.5
k8s-worker-2 ansible_host=10.101.10.6 ip=192.168.0.6 external_ip=10.101.10.6
```

#### [cluster:children]

The `[cluster:children]` section contains the following node roles presented in cluster:
* balancer (if any presented)
* control-plane
* worker (if any presented)

For example:

```ini
[cluster:children]
balancer
control-plane
worker
```

#### [balancer], [control-plane], [worker]

The `[balancer]`, `[control-plane]`, `[worker]` sections contain nodes names, which are included in this sections.

For example:

```ini
[balancer]
k8s-lb

[control-plane]
k8s-control-plane-1
k8s-control-plane-2
k8s-control-plane-3

[worker]
k8s-worker-1
k8s-worker-2
```

#### [cluster:vars]

The `[cluster:vars]` section contains other cluster-specific information:
* Username for connection
* Path to SSH key-file for connection (this data is used from `node_defaults` section from the original inventory)
* Services parameters
* Plugins parameters

For example:

```ini
[cluster:vars]
ansible_become=true
ansible_ssh_user=centos
ansible_ssh_private_key_file=/home/username/.ssh/id_rsa
```

All the data from the original inventory is included in the parameters of services and plugins, either explicitly defined by the user or automatically calculated.
They are either explicitly converted to a string type, or converted to JSON if it is list or dict.
The parameter values are presented as follows:

For example:

```ini
[cluster:vars]
...

# services.kubeadm
kubeadm_apiVersion=kubeadm.k8s.io/v1beta2
kubeadm_kind=ClusterConfiguration
kubeadm_kubernetesVersion=v1.16.3
kubeadm_networking={"podSubnet": "10.128.0.0/14", "serviceSubnet": "172.30.0.0/16"}
kubeadm_apiServer={"certSANs": ["192.168.0.1", "k8s-lb", "10.101.10.1"]}
kubeadm_imageRepository=example.com:5443
kubeadm_controlPlaneEndpoint=k8s.example.com:6443

# services.cri
cri_containerRuntime=containerd
cri_dockerConfig={"ipv6": false, "log-driver": "json-file", "log-opts": {"max-size": "64m", "max-file": "3"}, "exec-opts": ["native.cgroupdriver=systemd"], "icc": false, "live-restore": true, "userland-proxy": false}
cri_containerdConfig={"version": 2, "plugins.\"io.containerd.grpc.v1.cri\"": {"sandbox_image": "registry.k8s.io/pause:3.2"}, "plugins.\"io.containerd.grpc.v1.cri\".registry.mirrors.\"artifactory.example.com:5443\"": {"endpoint": ["https://artifactory.example.com:5443"]}, "plugins.\"io.containerd.grpc.v1.cri\".containerd.runtimes.runc": {"runtime_type": "io.containerd.runc.v2"}, "plugins.\"io.containerd.grpc.v1.cri\".containerd.runtimes.runc.options": {"SystemdCgroup": true}}
```

**Note**: From the final variables list the following parameters are excluded:

* `install`
* `installation`

## Cumulative Points

Cumulative points is a special feature that allows you to combine several repeating actions of the same type into one, and run at the right moment of installation.
For example, if you have 3 tasks, each of which requires a system reboot in order for their configurations to apply. So instead of repeating reboot 3 times in a row, you can do 1 reboot after these 3 tasks.
The description of cumulative points is as follows:

|Method|Scheduled by Tasks|Executed before tasks|Description|
|---|---|---|---|
|os.reboot_nodes|prepare.system.setup_selinux<br>prepare.system.disable_firewalld<br>prepare.system.disable_swap<br>prepare.system.modprobe<br>prepare.system.sysctl|prepare.system.sysctl|Reboots all cluster nodes.|
|os.verify_system|prepare.system.setup_selinux<br>prepare.system.disable_firewalld<br>prepare.system.disable_swap<br>prepare.system.modprobe<br>prepare.system.sysctl|prepare.system.sysctl|Verifies that configured system configurations have been applied.|

Cumulative points are not necessarily always executed. Tasks independently decide when to schedule a cumulative point.
For example, if the configurations are not updated, then a reboot for applying them is also not required.
For more detailed information, see the description of the tasks and their parameters.
If the task is skipped, then it is not able to schedule the cumulative point. For example, by skipping certain tasks, you can avoid a reboot.


# Supported Versions

**Note**: You can specify Kubernetes version via `kubernetesVersion` parameter. See [Kubernetes version](#kubernetes-version) section for more details.

**Note**: If you need to upgrade an existing Kubernetes cluster to new version, please use the [Upgrade Procedure](Maintenance.md#upgrade-procedure).

The tables below shows the correspondence of versions that are supported and is used during the installation:

## Default Dependent Components Versions for Kubernetes Versions v1.23.17
| Type     | Name                                                           | Versions         |                              |              |              |                   |           |           | Note                                                                                                       |
|----------|----------------------------------------------------------------|------------------|------------------------------|--------------|--------------|-------------------|-----------|-----------|------------------------------------------------------------------------------------------------------------|
|          |                                                                | CentOS RHEL 7.5+ | CentOS RHEL Oracle Linux 8.4 | Ubuntu 20.04 | Ubuntu 22.04 | Oracle Linux 7.5+ | RHEL 8.6+ | RockyLinux 8.7 |                                                                                                            |
| binaries | kubeadm                                                        | v1.23.17         | v1.23.17                     | v1.23.17     | v1.23.17     | v1.23.17          | v1.23.17  | v1.23.17  | SHA1: 0e805ff79d4099747bdf67d71d8acdc690e07e14                                                             |
|          | kubelet                                                        | v1.23.17         | v1.23.17                     | v1.23.17     | v1.23.17     | v1.23.17          | v1.23.17  | v1.23.17  | SHA1: 42bce3cef79c9bf2c787e2bcb923ef2528834e96                                                             |
|          | kubectl                                                        | v1.23.17         | v1.23.17                     | v1.23.17     | v1.23.17     | v1.23.17          | v1.23.17  | v1.23.17  | SHA1: 7377f28047c9c468978199cf5b9e4e7cae0c4e78                                                             |
|          | calicoctl                                                      | v3.24.2          | v3.24.2                      | v3.24.2      | v3.24.2      | v3.24.2           | v3.24.2   | v3.24.2   | SHA1: c4de7a203e5a3a942fdf130bc9ec180111fc2ab6  Required only if calico is installed.                      |
|          | crictl                                                         | v1.23.0          | v1.23.0                      | v1.23.0      | v1.23.0      | v1.23.0           | v1.23.0   | v1.23.0   | SHA1: 332001091d2e4523cbe8d97ab0f7bfbf4dfebda2 Required only if containerd is used as a container runtime. |
| rpms     | docker-ce                                                      | 20.10            | 20.10                        | 20.10        | 20.10        | 20.10             | 20.10     | 20.10     |                                                                                                            |
|          | containerd.io                                                  | 1.6.*            | 1.6.*                        | 1.5.*        | 1.5.*        | 1.6.*             | 1.6.*     | 1.6.*     |                                                                                                            |
|          | haproxy/rh-haproxy                                             | 1.8              | 1.8                          | 2.*          | 2.*          | 1.8               | 1.8       | 1.8       | Required only if balancers are presented in the deployment scheme.                                         |
|          | keepalived                                                     | 1.3              | 2.1                          | 2.*          | 2.*          | 1.3               | 2.1       | 2.1       | Required only if VRRP is presented in the deployment scheme.                                               |
| images   | registry.k8s.io/kube-apiserver                                      | v1.23.17         | v1.23.17                     | v1.23.17     | v1.23.17     | v1.23.17          | v1.23.17  | v1.23.17  |                                                                                                            |
|          | registry.k8s.io/kube-controller-manager                             | v1.23.17         | v1.23.17                     | v1.23.17     | v1.23.17     | v1.23.17          | v1.23.17  | v1.23.17  |                                                                                                            |
|          | registry.k8s.io/kube-proxy                                          | v1.23.17         | v1.23.17                     | v1.23.17     | v1.23.17     | v1.23.17          | v1.23.17  | v1.23.17  |                                                                                                            |
|          | registry.k8s.io/kube-scheduler                                      | v1.23.17         | v1.23.17                     | v1.23.17     | v1.23.17     | v1.23.17          | v1.23.17  | v1.23.17  |                                                                                                            |
|          | registry.k8s.io/coredns                                             | 1.8.6            | 1.8.6                        | 1.8.6        | 1.8.6        | 1.8.6             | 1.8.6     | 1.8.6     |                                                                                                            |
|          | registry.k8s.io/pause                                               | 3.6              | 3.6                          | 3.6          | 3.6          | 3.6               | 3.6       | 3.6       |                                                                                                            |
|          | registry.k8s.io/etcd                                                | 3.5.6-0          | 3.5.6-0                      | 3.5.6-0      | 3.5.6-0      | 3.5.6-0           | 3.5.6-0   | 3.5.6-0   |                                                                                                            |
|          | calico/typha                                                   | v3.24.2          | v3.24.2                      | v3.24.2      | v3.24.2      | v3.24.2           | v3.24.2   | v3.24.2   | Required only if Typha is enabled in Calico config.                                                        |
|          | calico/cni                                                     | v3.24.2          | v3.24.2                      | v3.24.2      | v3.24.2      | v3.24.2           | v3.24.2   | v3.24.2   |                                                                                                            |
|          | calico/node                                                    | v3.24.2          | v3.24.2                      | v3.24.2      | v3.24.2      | v3.24.2           | v3.24.2   | v3.24.2   |                                                                                                            |
|          | calico/kube-controllers                                        | v3.24.2          | v3.24.2                      | v3.24.2      | v3.24.2      | v3.24.2           | v3.24.2   | v3.24.2   |                                                                                                            |
|          | quay.io/kubernetes-ingress-controller/nginx-ingress-controller | v1.2.0           | v1.2.0                       | v1.2.0       | v1.2.0       | v1.2.0            | v1.2.0    | v1.2.0    |                                                                                                            |
|          | kubernetesui/dashboard                                         | v2.5.1           | v2.5.1                       | v2.5.1       | v2.5.1       | v2.5.1            | v2.5.1    | v2.5.1    | Required only if Kubernetes Dashboard plugin is set to be installed.                                       |
|          | kubernetesui/metrics-scraper                                   | v1.0.7           | v1.0.7                       | v1.0.7       | v1.0.7       | v1.0.7            | v1.0.7    | v1.0.7    | Required only if Kubernetes Dashboard plugin is set to be installed.                                       |
|          | rancher/local-path-provisioner                                 | v0.0.22          | v0.0.22                      | v0.0.22      | v0.0.22      | v0.0.22           | v0.0.22   | v0.0.22   | Required only if local-path provisioner plugin is set to be installed.                                     |

## Default Dependent Components Versions for Kubernetes Versions v1.24.11
| Type     | Name                                                           | Versions         |                              |              |              |                   |           |           | Note                                                                                                       |
|----------|----------------------------------------------------------------|------------------|------------------------------|--------------|--------------|-------------------|-----------|-----------|------------------------------------------------------------------------------------------------------------|
|          |                                                                | CentOS RHEL 7.5+ | CentOS RHEL Oracle Linux 8.4 | Ubuntu 20.04 | Ubuntu 22.04 | Oracle Linux 7.5+ | RHEL 8.6+ | RockyLinux 8.7 |                                                                                                            |
| binaries | kubeadm                                                        | v1.24.11         | v1.24.11                     | v1.24.11     | v1.24.11     | v1.24.11          | v1.24.11  | v1.24.11  | SHA1: 7d44b41e36ff71f5f00671d518f2e59b4540653a                                                             |
|          | kubelet                                                        | v1.24.11         | v1.24.11                     | v1.24.11     | v1.24.11     | v1.24.11          | v1.24.11  | v1.24.11  | SHA1: 3f332cbeed2f09b5275d56872bb8adcf54c9c98d                                                             |
|          | kubectl                                                        | v1.24.11         | v1.24.11                     | v1.24.11     | v1.24.11     | v1.24.11          | v1.24.11  | v1.24.11  | SHA1: 3f5d977d9ec38937ecf1dc9ccc3d0f0e48b88655                                                             |
|          | calicoctl                                                      | v3.24.2          | v3.24.2                      | v3.24.2      | v3.24.2      | v3.24.2           | v3.24.2   | v3.24.2   | SHA1: c4de7a203e5a3a942fdf130bc9ec180111fc2ab6 Required only if calico is installed.                       |
|          | crictl                                                         | v1.25.0          | v1.25.0                      | v1.25.0      | v1.25.0      | v1.25.0           | v1.25.0   | v1.25.0   | SHA1: b3a24e549ca3b4dfd105b7f4639014c0c508bea3 Required only if containerd is used as a container runtime. |
| rpms     | docker-ce                                                      | 20.10            | 20.10                        | 20.10        | 20.10        | 20.10             | 20.10     | 20.10     |                                                                                                            |
|          | containerd.io                                                  | 1.6.*            | 1.6.*                        | 1.6.*        | 1.6.*        | 1.6.*             | 1.6.*     | 1.6.*     |                                                                                                            |
|          | haproxy/rh-haproxy                                             | 1.8              | 1.8                          | 2.*          | 2.*          | 1.8               | 1.8       | 1.8       | Required only if balancers are presented in the deployment scheme.                                         |
|          | keepalived                                                     | 1.3              | 2.1                          | 2.*          | 2.*          | 1.3               | 2.1       | 2.1       | Required only if VRRP is presented in the deployment scheme.                                               |
| images   | registry.k8s.io/kube-apiserver                                      | v1.24.11         | v1.24.11                     | v1.24.11     | v1.24.11     | v1.24.11          | v1.24.11  | v1.24.11  |                                                                                                            |
|          | registry.k8s.io/kube-controller-manager                             | v1.24.11         | v1.24.11                     | v1.24.11     | v1.24.11     | v1.24.11          | v1.24.11  | v1.24.11  |                                                                                                            |
|          | registry.k8s.io/kube-proxy                                          | v1.24.11         | v1.24.11                     | v1.24.11     | v1.24.11     | v1.24.11          | v1.24.11  | v1.24.11  |                                                                                                            |
|          | registry.k8s.io/kube-scheduler                                      | v1.24.11         | v1.24.11                     | v1.24.11     | v1.24.11     | v1.24.11          | v1.24.11  | v1.24.11  |                                                                                                            |
|          | registry.k8s.io/coredns                                             | 1.8.6            | 1.8.6                        | 1.8.6        | 1.8.6        | 1.8.6             | 1.8.6     | 1.8.6     |                                                                                                            |
|          | registry.k8s.io/pause                                               | 3.7              | 3.7                          | 3.7          | 3.7          | 3.7               | 3.7       | 3.7       |                                                                                                            |
|          | registry.k8s.io/etcd                                                | 3.5.6-0          | 3.5.6-0                      | 3.5.6-0      | 3.5.6-0      | 3.5.6-0           | 3.5.6-0   | 3.5.6-0   |                                                                                                            |
|          | calico/typha                                                   | v3.24.2          | v3.24.2                      | v3.24.2      | v3.24.2      | v3.24.2           | v3.24.2   | v3.24.2   | Required only if Typha is enabled in Calico config.                                                        |
|          | calico/cni                                                     | v3.24.2          | v3.24.2                      | v3.24.2      | v3.24.2      | v3.24.2           | v3.24.2   | v3.24.2   |                                                                                                            |
|          | calico/node                                                    | v3.24.2          | v3.24.2                      | v3.24.2      | v3.24.2      | v3.24.2           | v3.24.2   | v3.24.2   |                                                                                                            |
|          | calico/kube-controllers                                        | v3.24.2          | v3.24.2                      | v3.24.2      | v3.24.2      | v3.24.2           | v3.24.2   | v3.24.2   |                                                                                                            |
|          | quay.io/kubernetes-ingress-controller/nginx-ingress-controller | v1.2.0           | v1.2.0                       | v1.2.0       | v1.2.0       | v1.2.0            | v1.2.0    | v1.2.0    |                                                                                                            |
|          | kubernetesui/dashboard                                         | v2.5.1           | v2.5.1                       | v2.5.1       | v2.5.1       | v2.5.1            | v2.5.1    | v2.5.1    | Required only if Kubernetes Dashboard plugin is set to be installed.                                       |
|          | kubernetesui/metrics-scraper                                   | v1.0.7           | v1.0.7                       | v1.0.7       | v1.0.7       | v1.0.7            | v1.0.7    | v1.0.7    | Required only if Kubernetes Dashboard plugin is set to be installed.                                       |
|          | rancher/local-path-provisioner                                 | v0.0.22          | v0.0.22                      | v0.0.22      | v0.0.22      | v0.0.22           | v0.0.22   | v0.0.22   | Required only if local-path provisioner plugin is set to be installed.                                     |

## Default Dependent Components Versions for Kubernetes Versions v1.25.7
| Type     | Name                                                           | Versions         |                              |              |              |                   |           |           | Note                                                                                                       |
|----------|----------------------------------------------------------------|------------------|------------------------------|--------------|--------------|-------------------|-----------|-----------|------------------------------------------------------------------------------------------------------------|
|          |                                                                | CentOS RHEL 7.5+ | CentOS RHEL Oracle Linux 8.4 | Ubuntu 20.04 | Ubuntu 22.04 | Oracle Linux 7.5+ | RHEL 8.6+ | RockyLinux 8.7 |                                                                                                            |
| binaries | kubeadm                                                        | v1.25.7          | v1.25.7                      | v1.25.7      | v1.25.7      | v1.25.7           | v1.25.7   | v1.25.7   | SHA1: 4efb3da49a50d137b728f0529bedee458e8c5f86                                                             |
|          | kubelet                                                        | v1.25.7          | v1.25.7                      | v1.25.7      | v1.25.7      | v1.25.7           | v1.25.7   | v1.25.7   | SHA1: ace8ce244896aca5d38c8184c44226660a09269a                                                             |
|          | kubectl                                                        | v1.25.7          | v1.25.7                      | v1.25.7      | v1.25.7      | v1.25.7           | v1.25.7   | v1.25.7   | SHA1: a5b32c173670ee6fa7710d7158ea4a0d198c8af5                                                             |
|          | calicoctl                                                      | v3.24.2          | v1.25.7                      | v1.25.7      | v1.25.7      | v1.25.7           | v1.25.7   | v1.25.7   | SHA1: c4de7a203e5a3a942fdf130bc9ec180111fc2ab6 Required only if calico is installed.                       |
|          | crictl                                                         | v1.25.0          | v1.25.0                      | v1.25.0      | v1.25.0      | v1.25.0           | v1.25.0   | v1.25.0   | SHA1: b3a24e549ca3b4dfd105b7f4639014c0c508bea3 Required only if containerd is used as a container runtime. |
| rpms     | docker-ce                                                      | 20.10            | 20.10                        | 20.10        | 20.10        | 20.10             | 20.10     | 20.10     |                                                                                                            |
|          | containerd.io                                                  | 1.6.*            | 1.6.*                        | 1.6.*        | 1.6.*        | 1.6.*             | 1.6.*     | 1.6.*     |                                                                                                            |
|          | haproxy/rh-haproxy                                             | 1.8              | 1.8                          | 2.*          | 2.*          | 1.8               | 1.8       | 1.8       | Required only if balancers are presented in the deployment scheme.                                         |
|          | keepalived                                                     | 1.3              | 2.1                          | 2.*          | 2.*          | 1.3               | 2.1       | 2.1       | Required only if VRRP is presented in the deployment scheme.                                               |
| images   | registry.k8s.io/kube-apiserver                                      | v1.25.7          | v1.25.7                      | v1.25.7      | v1.25.7      | v1.25.7           | v1.25.7   | v1.25.7   |                                                                                                            |
|          | registry.k8s.io/kube-controller-manager                             | v1.25.7          | v1.25.7                      | v1.25.7      | v1.25.7      | v1.25.7           | v1.25.7   | v1.25.7   |                                                                                                            |
|          | registry.k8s.io/kube-proxy                                          | v1.25.7          | v1.25.7                      | v1.25.7      | v1.25.7      | v1.25.7           | v1.25.7   | v1.25.7   |                                                                                                            |
|          | registry.k8s.io/kube-scheduler                                      | v1.25.7          | v1.25.7                      | v1.25.7      | v1.25.7      | v1.25.7           | v1.25.7   | v1.25.7   |                                                                                                            |
|          | registry.k8s.io/coredns                                             | v1.9.3           | v1.9.3                       | v1.9.3       | v1.9.3       | v1.9.3            | v1.9.3    | v1.9.3    |                                                                                                            |
|          | registry.k8s.io/pause                                               | 3.8              | 3.8                          | 3.8          | 3.8          | 3.8               | 3.8       | 3.8       |                                                                                                            |
|          | registry.k8s.io/etcd                                                | 3.5.6-0          | 3.5.6-0                      | 3.5.6-0      | 3.5.6-0      | 3.5.6-0           | 3.5.6-0   | 3.5.6-0   |                                                                                                            |
|          | calico/typha                                                   | v3.24.2          | v3.24.2                      | v3.24.2      | v3.24.2      | v3.24.2           | v3.24.2   | v3.24.2   | Required only if Typha is enabled in Calico config.                                                        |
|          | calico/cni                                                     | v3.24.2          | v3.24.2                      | v3.24.2      | v3.24.2      | v3.24.2           | v3.24.2   | v3.24.2   |                                                                                                            |
|          | calico/node                                                    | v3.24.2          | v3.24.2                      | v3.24.2      | v3.24.2      | v3.24.2           | v3.24.2   | v3.24.2   |                                                                                                            |
|          | calico/kube-controllers                                        | v3.24.2          | v3.24.2                      | v3.24.2      | v3.24.2      | v3.24.2           | v3.24.2   | v3.24.2   |                                                                                                            |
|          | quay.io/kubernetes-ingress-controller/nginx-ingress-controller | v1.4.0           | v1.4.0                       | v1.4.0       | v1.4.0       | v1.4.0            | v1.4.0    | v1.4.0    |                                                                                                            |
|          | kubernetesui/dashboard                                         | v2.7.0           | v2.7.0                       | v2.7.0       | v2.7.0       | v2.7.0            | v2.7.0    | v2.7.0    | Required only if Kubernetes Dashboard plugin is set to be installed.                                       |
|          | kubernetesui/metrics-scraper                                   | v1.0.8           | v1.0.8                       | v1.0.8       | v1.0.8       | v1.0.8            | v1.0.8    | v1.0.8    | Required only if Kubernetes Dashboard plugin is set to be installed.                                       |
|          | rancher/local-path-provisioner                                 | v0.0.23          | v0.0.23                      | v0.0.23      | v0.0.23      | v0.0.23           | v0.0.23   | v0.0.23   | Required only if local-path provisioner plugin is set to be installed.                                     |

## Default Dependent Components Versions for Kubernetes Versions v1.26.7
| Type     | Name                                                           | Versions         |                              |              |              |                   |           |           | Note                                                                                                       |
|----------|----------------------------------------------------------------|------------------|------------------------------|--------------|--------------|-------------------|-----------|-----------|------------------------------------------------------------------------------------------------------------|
|          |                                                                | CentOS RHEL 7.5+ | CentOS RHEL Oracle Linux 8.4 | Ubuntu 20.04 | Ubuntu 22.04 | Oracle Linux 7.5+ | RHEL 8.6+ | RockyLinux 8.7 |                                                                                                            |
| binaries | kubeadm                                                        | v1.26.7          | v1.26.7                      | v1.26.7      | v1.26.7      | v1.26.7           | v1.26.7   | v1.26.7   | SHA1: 623952b584e5604da1e3e9e52c6da8dbecadf361                                                             |
|          | kubelet                                                        | v1.26.7          | v1.26.7                      | v1.26.7      | v1.26.7      | v1.26.7           | v1.26.7   | v1.26.7   | SHA1: 4e82efbb2f5880b5eec10ce4e73ba6f87ad9fbbe                                                             |
|          | kubectl                                                        | v1.26.7          | v1.26.7                      | v1.26.7      | v1.26.7      | v1.26.7           | v1.26.7   | v1.26.7   | SHA1: 33c088e6d025b90e4311c4823d712d4b7a32e886                                                            |
|          | calicoctl                                                      | v3.26.1          | v3.26.1                      | v3.26.1      | v3.26.1      | v3.26.1           | v3.26.1   | v3.26.1   | SHA1: 4b9896ef195ec4fc4ff0d255c81960ebb5750922 Required only if calico is installed.                       |
|          | crictl                                                         | v1.27.1          | v1.27.1                      | v1.27.1      | v1.27.1      | v1.27.1           | v1.27.1   | v1.27.1   | SHA1: c350624a1b8dff38dd58447d63518dc330cc5c0f Required only if containerd is used as a container runtime. |
| rpms     | docker-ce                                                      | 20.10            | 20.10                        | 20.10        | 20.10        | 20.10             | 20.10     | 20.10     |                                                                                                            |
|          | containerd.io                                                  | 1.6.*            | 1.6.*                        | 1.6.*        | 1.6.*        | 1.6.*             | 1.6.*     | 1.6.*     |                                                                                                            |
|          | haproxy/rh-haproxy                                             | 1.8              | 1.8                          | 2.*          | 2.*          | 1.8               | 1.8       | 1.8       | Required only if balancers are presented in the deployment scheme.                                         |
|          | keepalived                                                     | 1.3              | 2.1                          | 2.*          | 2.*          | 1.3               | 2.1       | 2.1       | Required only if VRRP is presented in the deployment scheme.                                               |
| images   | registry.k8s.io/kube-apiserver                                      | v1.26.7          | v1.26.7                      | v1.26.7      | v1.26.7      | v1.26.7           | v1.26.7   | v1.26.7   |                                                                                                            |
|          | registry.k8s.io/kube-controller-manager                             | v1.26.7          | v1.26.7                      | v1.26.7      | v1.26.7      | v1.26.7           | v1.26.7   | v1.26.7   |                                                                                                            |
|          | registry.k8s.io/kube-proxy                                          | v1.26.7          | v1.26.7                      | v1.26.7      | v1.26.7      | v1.26.7           | v1.26.7   | v1.26.7   |                                                                                                            |
|          | registry.k8s.io/kube-scheduler                                      | v1.26.7          | v1.26.7                      | v1.26.7      | v1.26.7      | v1.26.7           | v1.26.7   | v1.26.7   |                                                                                                            |
|          | registry.k8s.io/coredns                                             | v1.9.3           | v1.9.3                       | v1.9.3       | v1.9.3       | v1.9.3            | v1.9.3    | v1.9.3    |                                                                                                            |
|          | registry.k8s.io/pause                                               | 3.9              | 3.9                          | 3.9          | 3.9          | 3.9               | 3.9       | 3.9       |                                                                                                            |
|          | registry.k8s.io/etcd                                                | 3.5.6-0          | 3.5.6-0                      | 3.5.6-0      | 3.5.6-0      | 3.5.6-0           | 3.5.6-0   | 3.5.6-0   |                                                                                                            |
|          | calico/typha                                                   | v3.26.1          | v3.26.1                      | v3.26.1      | v3.26.1      | v3.26.1           | v3.26.1   | v3.26.1   | Required only if Typha is enabled in Calico config.                                                        |
|          | calico/cni                                                     | v3.26.1          | v3.26.1                      | v3.26.1      | v3.26.1      | v3.26.1           | v3.26.1   | v3.26.1   |                                                                                                            |
|          | calico/node                                                    | v3.26.1          | v3.26.1                      | v3.26.1      | v3.26.1      | v3.26.1           | v3.26.1   | v3.26.1   |                                                                                                            |
|          | calico/kube-controllers                                        | v3.26.1          | v3.26.1                      | v3.26.1      | v3.26.1      | v3.26.1           | v3.26.1   | v3.26.1   |                                                                                                            |
|          | quay.io/kubernetes-ingress-controller/nginx-ingress-controller | v1.8.1           | v1.8.1                       | v1.8.1       | v1.8.1       | v1.8.1            | v1.8.1    | v1.8.1    |                                                                                                            |
|          | kubernetesui/dashboard                                         | v2.7.0           | v2.7.0                       | v2.7.0       | v2.7.0       | v2.7.0            | v2.7.0    | v2.7.0    | Required only if Kubernetes Dashboard plugin is set to be installed.                                       |
|          | kubernetesui/metrics-scraper                                   | v1.0.8           | v1.0.8                       | v1.0.8       | v1.0.8       | v1.0.8            | v1.0.8    | v1.0.8    | Required only if Kubernetes Dashboard plugin is set to be installed.                                       |
|          | rancher/local-path-provisioner                                 | v0.0.24          | v0.0.24                      | v0.0.24      | v0.0.24      | v0.0.24           | v0.0.24   | v0.0.24   | Required only if local-path provisioner plugin is set to be installed.                                     |

## Default Dependent Components Versions for Kubernetes Versions v1.27.4
| Type     | Name                                                           | Versions         |                              |              |              |                   |           |           | Note                                                                                                       |
|----------|----------------------------------------------------------------|------------------|------------------------------|--------------|--------------|-------------------|-----------|-----------|------------------------------------------------------------------------------------------------------------|
|          |                                                                | CentOS RHEL 7.5+ | CentOS RHEL Oracle Linux 8.4 | Ubuntu 20.04 | Ubuntu 22.04 | Oracle Linux 7.5+ | RHEL 8.6+ | RockyLinux 8.7 |                                                                                                            |
| binaries | kubeadm                                                        | v1.27.4          | v1.27.4                      | v1.27.4      | v1.27.4      | v1.27.4           | v1.27.4   | v1.27.4   | SHA1: a6e7a3f19a7febc71a61cc53b08cc1e856b14e97                                                             |
|          | kubelet                                                        | v1.27.4          | v1.27.4                      | v1.27.4      | v1.27.4      | v1.27.4           | v1.27.4   | v1.27.4   | SHA1: 86395c58aeb225c9b2c6aae2574e9a86492b5ca8                                                             |
|          | kubectl                                                        | v1.27.4          | v1.27.4                      | v1.27.4      | v1.27.4      | v1.27.4           | v1.27.4   | v1.27.4   | SHA1: 1ad67e417c2833ddbc26ca6d161e4067639e5d23                                                            |
|          | calicoctl                                                      | v3.26.1          | v3.26.1                      | v3.26.1      | v3.26.1      | v3.26.1           | v3.26.1   | v3.26.1   | SHA1: 4b9896ef195ec4fc4ff0d255c81960ebb57509226 Required only if calico is installed.                       |
|          | crictl                                                         | v1.27.1          | v1.27.1                      | v1.27.1      | v1.27.1      | v1.27.1           | v1.27.1   | v1.27.1   | SHA1: c350624a1b8dff38dd58447d63518dc330cc5c0f Required only if containerd is used as a container runtime. |
| rpms     | docker-ce                                                      | 20.10            | 20.10                        | 20.10        | 20.10        | 20.10             | 20.10     | 20.10     |                                                                                                            |
|          | containerd.io                                                  | 1.6.*            | 1.6.*                        | 1.6.*        | 1.6.*        | 1.6.*             | 1.6.*     | 1.6.*     |                                                                                                            |
|          | haproxy/rh-haproxy                                             | 1.8              | 1.8                          | 2.*          | 2.*          | 1.8               | 1.8       | 1.8       | Required only if balancers are presented in the deployment scheme.                                         |
|          | keepalived                                                     | 1.3              | 2.1                          | 2.*          | 2.*          | 1.3               | 2.1       | 2.1       | Required only if VRRP is presented in the deployment scheme.                                               |
| images   | registry.k8s.io/kube-apiserver                                      | v1.27.4          | v1.27.4                      | v1.27.4      | v1.27.4      | v1.27.4           | v1.27.4   | v1.27.4   |                                                                                                            |
|          | registry.k8s.io/kube-controller-manager                             | v1.27.4          | v1.27.4                      | v1.27.4      | v1.27.4      | v1.27.4           | v1.27.4   | v1.27.4   |                                                                                                            |
|          | registry.k8s.io/kube-proxy                                          | v1.27.4          | v1.27.4                      | v1.27.4      | v1.27.4      | v1.27.4           | v1.27.4   | v1.27.4   |                                                                                                            |
|          | registry.k8s.io/kube-scheduler                                      | v1.27.4          | v1.27.4                      | v1.27.4      | v1.27.4      | v1.27.4           | v1.27.4   | v1.27.4   |                                                                                                            |
|          | registry.k8s.io/coredns                                             | v1.10.1          | v1.10.1                      | v1.10.1      | v1.10.1      | v1.10.1           | v1.10.1   | v1.10.1   |                                                                                                            |
|          | registry.k8s.io/pause                                               | 3.9              | 3.9                          | 3.9          | 3.9          | 3.9               | 3.9       | 3.9       |                                                                                                            |
|          | registry.k8s.io/etcd                                                | 3.5.7-0          | 3.5.7-0                      | 3.5.7-0      | 3.5.7-0      | 3.5.7-0           | 3.5.7-0   | 3.5.7-0   |                                                                                                            |
|          | calico/typha                                                   | v3.26.1          | v3.26.1                      | v3.26.1      | v3.26.1      | v3.26.1           | v3.26.1   | v3.26.1   | Required only if Typha is enabled in Calico config.                                                        |
|          | calico/cni                                                     | v3.26.1          | v3.26.1                      | v3.26.1      | v3.26.1      | v3.26.1           | v3.26.1   | v3.26.1   |                                                                                                            |
|          | calico/node                                                    | v3.26.1          | v3.26.1                      | v3.26.1      | v3.26.1      | v3.26.1           | v3.26.1   | v3.26.1   |                                                                                                            |
|          | calico/kube-controllers                                        | v3.26.1          | v3.26.1                      | v3.26.1      | v3.26.1      | v3.26.1           | v3.26.1   | v3.26.1   |                                                                                                            |
|          | quay.io/kubernetes-ingress-controller/nginx-ingress-controller | v1.8.1           | v1.8.1                       | v1.8.1       | v1.8.1       | v1.8.1            | v1.8.1    | v1.8.1    |                                                                                                            |
|          | kubernetesui/dashboard                                         | v2.7.0           | v2.7.0                       | v2.7.0       | v2.7.0       | v2.7.0            | v2.7.0    | v2.7.0    | Required only if Kubernetes Dashboard plugin is set to be installed.                                       |
|          | kubernetesui/metrics-scraper                                   | v1.0.8           | v1.0.8                       | v1.0.8       | v1.0.8       | v1.0.8            | v1.0.8    | v1.0.8    | Required only if Kubernetes Dashboard plugin is set to be installed.                                       |
|          | rancher/local-path-provisioner                                 | v0.0.24          | v0.0.24                      | v0.0.24      | v0.0.24      | v0.0.24           | v0.0.24   | v0.0.24   | Required only if local-path provisioner plugin is set to be installed.                                     |

## Default Dependent Components Versions for Kubernetes Versions v1.28.0
| Type     | Name                                                           | Versions         |                              |              |              |                   |           |           | Note                                                                                                       |
|----------|----------------------------------------------------------------|------------------|------------------------------|--------------|--------------|-------------------|-----------|-----------|------------------------------------------------------------------------------------------------------------|
|          |                                                                | CentOS RHEL 7.5+ | CentOS RHEL Oracle Linux 8.4 | Ubuntu 20.04 | Ubuntu 22.04 | Oracle Linux 7.5+ | RHEL 8.6+ | RockyLinux 8.7 |                                                                                                            |
| binaries | kubeadm                                                        | v1.28.0          | v1.28.0                      | v1.28.0      | v1.28.0      | v1.28.0           | v1.28.0   | v1.28.0   | SHA1: e03127bc6605f4518c449e543c142ec69bf37798                                                            |
|          | kubelet                                                        | v1.28.0          | v1.28.0                      | v1.28.0      | v1.28.0      | v1.28.0           | v1.28.0   | v1.28.0   | SHA1: d096ad117047f368a5c4c37d511aacd612691aba                                                            |
|          | kubectl                                                        | v1.28.0          | v1.28.0                      | v1.28.0      | v1.28.0      | v1.28.0           | v1.28.0   | v1.28.0   | SHA1: c456a5e8541a6c9fbcf199ff65b37559bdd29925                                                            |
|          | calicoctl                                                      | v3.26.1          | v3.26.1                      | v3.26.1      | v3.26.1      | v3.26.1           | v3.26.1   | v3.26.1   | SHA1: 4b9896ef195ec4fc4ff0d255c81960ebb57509226 Required only if calico is installed.                       |
|          | crictl                                                         | v1.27.1          | v1.27.1                      | v1.27.1      | v1.27.1      | v1.27.1           | v1.27.1   | v1.27.1   | SHA1: c350624a1b8dff38dd58447d63518dc330cc5c0f Required only if containerd is used as a container runtime. |
| rpms     | docker-ce                                                      | 20.10            | 20.10                        | 20.10        | 20.10        | 20.10             | 20.10     | 20.10     |                                                                                                            |
|          | containerd.io                                                  | 1.6.*            | 1.6.*                        | 1.6.*        | 1.6.*        | 1.6.*             | 1.6.*     | 1.6.*     |                                                                                                            |
|          | haproxy/rh-haproxy                                             | 1.8              | 1.8                          | 2.*          | 2.*          | 1.8               | 1.8       | 1.8       | Required only if balancers are presented in the deployment scheme.                                         |
|          | keepalived                                                     | 1.3              | 2.1                          | 2.*          | 2.*          | 1.3               | 2.1       | 2.1       | Required only if VRRP is presented in the deployment scheme.                                               |
| images   | registry.k8s.io/kube-apiserver                                      | v1.28.0          | v1.28.0                      | v1.28.0      | v1.28.0      | v1.28.0           | v1.28.0   | v1.28.0   |                                                                                                            |
|          | registry.k8s.io/kube-controller-manager                             | v1.28.0          | v1.28.0                      | v1.28.0      | v1.28.0      | v1.28.0           | v1.28.0   | v1.28.0   |                                                                                                            |
|          | registry.k8s.io/kube-proxy                                          | v1.28.0          | v1.28.0                      | v1.28.0      | v1.28.0      | v1.28.0           | v1.28.0   | v1.28.0   |                                                                                                            |
|          | registry.k8s.io/kube-scheduler                                      | v1.28.0          | v1.28.0                      | v1.28.0      | v1.28.0      | v1.28.0           | v1.28.0   | v1.28.0   |                                                                                                            |
|          | registry.k8s.io/coredns                                             | v1.10.1          | v1.10.1                      | v1.10.1      | v1.10.1      | v1.10.1           | v1.10.1   | v1.10.1   |                                                                                                            |
|          | registry.k8s.io/pause                                               | 3.9              | 3.9                          | 3.9          | 3.9          | 3.9               | 3.9       | 3.9       |                                                                                                            |
|          | registry.k8s.io/etcd                                                | 3.5.9-0          | 3.5.9-0                      | 3.5.9-0      | 3.5.9-0      | 3.5.9-0           | 3.5.9-0   | 3.5.9-0   |                                                                                                            |
|          | calico/typha                                                   | v3.26.1          | v3.26.1                      | v3.26.1      | v3.26.1      | v3.26.1           | v3.26.1   | v3.26.1   | Required only if Typha is enabled in Calico config.                                                        |
|          | calico/cni                                                     | v3.26.1          | v3.26.1                      | v3.26.1      | v3.26.1      | v3.26.1           | v3.26.1   | v3.26.1   |                                                                                                            |
|          | calico/node                                                    | v3.26.1          | v3.26.1                      | v3.26.1      | v3.26.1      | v3.26.1           | v3.26.1   | v3.26.1   |                                                                                                            |
|          | calico/kube-controllers                                        | v3.26.1          | v3.26.1                      | v3.26.1      | v3.26.1      | v3.26.1           | v3.26.1   | v3.26.1   |                                                                                                            |
|          | quay.io/kubernetes-ingress-controller/nginx-ingress-controller | v1.8.1           | v1.8.1                       | v1.8.1       | v1.8.1       | v1.8.1            | v1.8.1    | v1.8.1    |                                                                                                            |
|          | kubernetesui/dashboard                                         | v2.7.0           | v2.7.0                       | v2.7.0       | v2.7.0       | v2.7.0            | v2.7.0    | v2.7.0    | Required only if Kubernetes Dashboard plugin is set to be installed.                                       |
|          | kubernetesui/metrics-scraper                                   | v1.0.8           | v1.0.8                       | v1.0.8       | v1.0.8       | v1.0.8            | v1.0.8    | v1.0.8    | Required only if Kubernetes Dashboard plugin is set to be installed.                                       |
|          | rancher/local-path-provisioner                                 | v0.0.24          | v0.0.24                      | v0.0.24      | v0.0.24      | v0.0.24           | v0.0.24   | v0.0.24   | Required only if local-path provisioner plugin is set to be installed.                                     |
