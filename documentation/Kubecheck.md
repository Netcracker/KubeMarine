This section provides information about the Kubecheck functionality.

- [Procedure Execution From CLI](#procedure-execution-from-cli)
- [Check Procedures](#check-procedures)
  - [IAAS Procedure](#iaas-procedure)
    - [001 Connectivity](#001-connectivity)
    - [002 Latency - Single Thread](#002-latency---single-thread)
    - [003 Latency - Multi Thread](#003-latency---multi-thread)
    - [004 Sudoer Access](#004-sudoer-access)
    - [005 Items Amount](#005-items-amount)
      - [005 VIPs Amount](#005-vips-amount)
      - [005 Balancers Amount](#005-balancers-amount)
      - [005 Control-planes Amount](#005-control-planes-amount)
      - [005 Workers Amount](#005-workers-amount)
      - [005 Total Nodes Amount](#005-total-nodes-amount)
    - [006 VCPUs Amount](#006-vcpus-amount)
      - [006 VCPUs Amount - Balancers](#006-vcpus-amount---balancers)
      - [006 VCPUs Amount - Control-planes](#006-vcpus-amount---control-planes)
      - [006 VCPUs Amount - Workers](#006-vcpus-amount---workers)
    - [007 RAM Amount](#007-ram-amount)
      - [007 RAM Amount - Balancers](#007-ram-amount---balancers)
      - [007 RAM Amount - Control-planes](#007-ram-amount---control-planes)
      - [007 RAM Amount - Workers](#007-ram-amount---workers)
    - [008 Distributive](#008-distributive)
    - [009 PodSubnet](#009-podsubnet)
    - [010 ServiceSubnet](#010-servicesubnet)
    - [011 TCPPorts](#011-tcpports)
    - [012 Thirdparties Availability](#012-thirdparties-availability)
    - [013 Package Repositories](#013-package-repositories)
    - [014 Package Availability](#014-package-availability)
    - [015 Kernel Version](#015-kernel-version)
  - [PAAS Procedure](#paas-procedure)
    - [201 Service Status](#201-service-status)
      - [201 Haproxy Status](#201-haproxy-status)
      - [201 Keepalived Status](#201-keepalived-status)
      - [201 Container Runtime Status](#201-container-runtime-status)
        - [204 Container Runtime Configuration Check](#204-container-runtime-configuration-check)
      - [201 Kubelet Status](#201-kubelet-status)
        - [202 Nodes pid_max](#202-nodes-pid_max)
        - [203 Kubelet Version](#203-kubelet-version)
    - [205 System Packages Versions](#205-system-packages-version)
      - [205 CRI Versions](#205-cri-versions)
      - [205 HAproxy Version](#205-haproxy-version)
      - [205 Keepalived Version](#205-keepalived-version)
      - [205 Audit Version](#205-audit-version)
      - [205 Mandatory Package Versions](#205-mandatory-package-versions)
    - [206 Generic Packages Version](#206-generic-packages-version)
    - [207 Pods Condition](#207-pods-condition)
    - [208 Dashboard Availability](#208-dashboard-availability)
    - [209 Nodes Existence](#209-nodes-existence)
    - [210 Nodes Roles](#210-nodes-roles)
    - [211 Nodes Condition](#211-nodes-condition)
      - [211 Nodes Condition - NetworkUnavailable](#211-nodes-condition---networkunavailable)
      - [211 Nodes Condition - MemoryPressure](#211-nodes-condition---memorypressure)
      - [211 Nodes Condition - DiskPressure](#211-nodes-condition---diskpressure)
      - [211 Nodes Condition - PIDPressure](#211-nodes-condition---pidpressure)
      - [211 Nodes Condition - Ready](#211-nodes-condition---ready)
    - [212 Thirdparties Hashes](#212-thirdparties-hashes)
    - [213 Selinux Security policy](#213-selinux-security-policy)
    - [214 Selinux Configuration](#214-selinux-configuration)
    - [215 Firewalld Status](#215-firewalld-status)
    - [216 Swap State](#216-swap-state)
    - [217 Modprobe Rules](#217-modprobe-rules)
    - [218 Time Difference](#218-time-difference)
    - [219 Health Status ETCD](#219-health-status-etcd)
    - [220 Control Plane Configuration Status](#220-control-plane-configuration-status)
    - [221 Control Plane Health Status](#221-control-plane-health-status)
    - [222 Default Services Configuration Status](#222-default-services-configuration-status)
    - [223 Default Services Health Status](#223-default-services-health-status)
    - [224 Calico Configuration Check](#224-calico-configuration-check)
      - [230 Calico API Server Health Status](#230-calico-api-server-health-status)
    - [225 Pod Security Admission Status](#225-pod-security-admission-status)
    - [226 Geo Connectivity Status](#226-geo-connectivity-status)
    - [227 Apparmor Status](#227-apparmor-status)
    - [228 Apparmor Configuration](#228-apparmor-configuration)
    - [229 Audit Policy Configuration](#229-audit-policy-configuration)
    - [231 Audit Daemon Rules](#231-audit-daemon-rules)
    - [232 Kernel Parameters Configuration](#232-kernel-parameters-configuration)
- [Report File Generation](#report-file-generation)
  - [HTML Report](#html-report)
  - [CSV Report](#csv-report)


# Kubernetes Check

The Kubernetes Check procedure provides an opportunity to automatically verify the environment and quickly get a report on the results. The environment is checked against the following criteria, which is defined in advance:

* Minimal - The minimum results that the test environment must meet. If it does not satisfy this, there is no guarantee that this environment will be operational.
* Recommended - The recommended results in which the test development environment for the Full-HA cluster scheme showed the best results and performance. If you have a production environment, you must independently calculate the number of resources for your cluster. This number is more than that recommended by the Kubernetes Check procedure.

If the detected test results deviate from the criteria, the following status types are assigned to them:

* **OK** - This status indicates the compliance with the recommended values, if any, and successful completion of the test without errors.
* **WARN** - This status indicates that the test deviated slightly from the expected values. For example, the results found do not correspond to the recommended values. However, this test passed the minimum requirements and has not failed.
* **FAIL** - This status indicates that the test does not meet the minimum requirements or it has failed. This test requires attention to fix the environment.
* **ERROR?** - This status indicates that an internal error occurred in the test and it cannot be continued.

At the end of the logs of the procedure, a summary report table with all the test results is displayed. For example:

```
           Group    Status   ID    Test                                                               Actual result        Minimal   Recommended
 
             SSH      OK     001  Connectivity .......................................................... Connected                             
             SSH     WARN    002  Latency - Single Thread .................................................. 1500ms          10000          1000
             SSH     FAIL    003  Latency - Multi Thread .................................................. 50000ms          15000          2000   

 OVERALL RESULTS:  1 SUCCEEDED   1 WARNED   1 FAILED  
```

The following columns are presented in this table:

* Group - The logical group of checks to which the test belongs.
* Status - The final status assigned to the test according to the results of the check.
* ID - The test identifier.
* Name - The short test name.
* Actual result - The actual value detected by the test on the environment.
* Minimal (optional) - The minimum required value for this test.
* Recommended (optional) - The recommended required value for this test.

The final report is generated in a file. For more information, see [Report File Generation](#report-file-generation).

### Procedure Execution From CLI

Check procedure execution form CLI can be started with the following command:

```bash
kubemarine check_iaas
kubemarine check_paas
```

It begins the execution of all tasks available in the procedure in accordance with the procedure type. For more information about how a tasks list can be redefined, see [Tasks List Redefinition](Installation.md#tasks-list-redefinition) in _Kubemarine Installation Procedure_.

**Note:** some `paas` checks work only if additional optional configuration file is provided.
Without additional configuration, such checks will be skipped without warning. 
See particular check documentation for configuration format. Following is an example of passing procedure config file:
```bash
kubemarine check_paas procedure.yaml
```

### Check Procedures

A check procedure is divided into logical sub-procedures. Each of them is responsible for its own set of tests conducted on the environment.

#### IAAS Procedure

The IAAS procedure verifies only the infrastructure. For example, it checks the amount of hardware resources or checks the speed of the environment. These tests do not perform cluster checks and are intended to be performed both on a completely empty environment and an environment with the cluster installed.

The task tree is as follows:

* ssh
  * connectivity
  * latency
    * single
    * multiple
  * sudoer_access
* network
  * pod_subnet_connectivity
  * service_subnet_connectivity
  * check_tcp_ports
  * thirdparties_available
* hardware
  * members_amount
    * vips
    * balancers
    * control-planes
    * workers
    * total
  * cpu
    * balancers
    * control-planes
    * workers
  * ram
    * balancers
    * control-planes
    * workers
* system
  * distributive
* thirdparties
  * availability

##### 001 Connectivity

*Task*: `ssh.connectivity`

This test checks whether it is possible to establish the SSH-connection with nodes. If you are unable to connect to the nodes, check and fix the following:

* The credentials for the connection are correct (verify the ip address, user, and key).
* The node is up.
* The node is online.
* The network connection to the node is available.
* The node port 22 (or other custom, if configured) is open and can be binded.
* The SSHD is running and its configuration is correct. 

##### 002 Latency - Single Thread

*Task*: `ssh.latency.single`

This test checks the delay between the nodes in the single-threaded mode. The test of the nodes passes one after another.

##### 003 Latency - Multi Thread

*Task*: `ssh.latency.multiple`

This test checks the delay between the nodes in the multi-threaded mode. The test of all nodes passes at the same time.

##### 004 Sudoer Access

*Task*: `ssh.sudoer_access`

##### 005 Items Amount

Tests of this type check the availability of the required amount of resources.

###### 005 VIPs Amount

*Task*: `hardware.members_amount.vips`

This test checks the number of VIPs present for Keepalived.

###### 005 Balancers Amount

*Task*: `hardware.members_amount.balancers`

This test checks the number of nodes present with the `balancer` role.

###### 005 Control-planes Amount

*Task*: `hardware.members_amount.control-planes`

This test checks the number of nodes present with the `control-plane` role.

###### 005 Workers Amount

*Task*: `hardware.members_amount.workers`

This test checks the number of nodes present with the `worker` role.

###### 005 Total Nodes Amount

*Task*: `hardware.members_amount.total`

This test checks the number of all the nodes present.

##### 006 VCPUs Amount

Tests of this type check the availability of the required number of processors.

###### 006 VCPUs Amount - Balancers

*Task*: `hardware.cpu.balancers`

This test checks the number of processors on the nodes with the `balancer` role.

###### 006 VCPUs Amount - Control-planes

*Task*: `hardware.cpu.control-planes`

This test checks the number of processors on the nodes with the `control-plane` role.

###### 006 VCPUs Amount - Workers

*Task*: `hardware.cpu.workers`

This test checks the number of processors on the nodes with the `worker` role.

##### 007 RAM Amount

Tests of this type check the availability of the required number of RAM.

###### 007 RAM Amount - Balancers

*Task*: `hardware.ram.balancers`

This test checks the amount of RAM on nodes with the `balancer` role.

###### 007 RAM Amount - Control-planes

*Task*: `hardware.ram.control-planes`

This test checks the amount of RAM on nodes with the `control-plane` role.

###### 007 RAM Amount - Workers

*Task*: `hardware.ram.workers`

This test checks the amount of RAM on nodes with the `worker` role.

##### 008 Distributive

*Task*: `system.distributive`

This test checks the family and release version of the operating system on the hosts.

##### 009 PodSubnet

*Task*: `network.pod_subnet_connectivity`

This test checks the connectivity between nodes inside a pod's subnetwork.

##### 010 ServiceSubnet

*Task*: `network.service_subnet_connectivity`

This test checks the connectivity between nodes inside the service's subnetwork.

##### 011 TCPPorts

*Task*: `network.check_tcp_ports`

This test checks if necessary ports are opened on the nodes.

##### 012 Thirdparties Availability

*Task*: `software.thirdparties.availability`

This test checks if thirdparties are available from sources on needed nodes.

##### 013 Package Repositories

*Task*: `software.packages.repositories`

This test checks if defined package repositories are available from nodes.

##### 014 Package Availability

*Task*: `software.packages.availability`

This test checks if needed package are available from nodes.

###### 015 Kernel version

*Task*: `software.kernel.version`

This test checks the Linux kernel version for an `unstable kernel version`, if it is equal to a unstable one, it issues a warning

`Unstable kernel version` - is a kernel with detected serious issue that affects any part of cluster, therefore it's unsupported


#### PAAS Procedure

The PAAS procedure verifies the platform solution. For example, it checks the health of a cluster or service statuses on nodes. This test checks the already configured environment. All services and the Kubernetes cluster must be installed and should be in working condition. Apart from the environment installed and configured by Kubemarine, the test can check other environments too.

The task tree is as follows:

* services
  * security
    * selinux
      * status
      * config
    * apparmor
      * status
      * config
    * firewalld
      * status
  * system
    * time
    * swap
      * status
    * modprobe
      * rules
  * haproxy
    * status
  * keepalived
    * status
  * container_runtime
    * status
    * configuration
  * kubelet
    * status
    * configuration
    * version
  * packages
    * system
      * recommended_versions
      * cri_version
      * haproxy_version
      * keepalived_version
      * audit_version
      * mandatory_versions
    * generic
      * version
* thirdparties
  * hashes
* kubernetes
  * pods
  * plugins
    * dashboard
  * nodes
    * existence
    * roles
    * condition
      * network
      * memory
      * disk
      * pid
      * ready
  * audit
    * policy
  * admission
* etcd
  * health_status
* control_plane
  * configuration_status
  * health_status
* default_services
  * configuration_status
  * health_status
* calico
  * config_check
  * apiserver
    * health_status
* geo_check

##### 201 Service Status

Tests of this type verify the correctness of service statuses.

###### 201 Haproxy Status

*Task*: `services.haproxy.status`

This test checks the status of the Haproxy service on all hosts in the cluster where this service is expected.

###### 201 Keepalived Status

*Task*: `services.keepalived.status`

This test checks the status of the Keepalived service on all hosts in the cluster where this service is expected.

###### 201 Container Runtime Status

*Task*: `services.container_runtime.status`

This test checks the status of the Container Runtime (docker/containerd) service on all hosts in the cluster where this service is expected.

###### 201 Kubelet Status

*Task*: `services.kubelet.status`

This test checks the status of the Kubelet service on all hosts in the cluster where this service is expected.

##### 202 Nodes pid_max

*Task*: `services.kubelet.configuration`

This test checks that kubelet `maxPods` and `podPidsLimit` are correctly aligned with kernel `pid_max`.

##### 203 Kubelet Version

*Task*: `services.kubelet.version`

This test checks the Kubelet version on all hosts in a cluster.

##### 204 Container Runtime Configuration Check

*Task*: `services.container_runtime.configuration`

This test checks that the configuration of the container runtime is actual
and matches the effectively resolved configuration from the inventory.

##### 205 System Packages Version

Tests of this type check that the system packages are installed, have equal versions and those versions are 
recommended and correspond with cluster.yaml.

###### 205 CRI Versions

*Task*: `services.packages.system.cri_version`

This test checks that the configured CRI package is installed on all nodes, has equal version and this version is 
recommended and corresponds with cluster.yaml.

###### 205 HAproxy Version

*Task*: `services.packages.system.haproxy_version`

This test checks that the configured HAproxy package is installed on all nodes, has equal version and this version is 
recommended and corresponds with cluster.yaml.

###### 205 Keepalived Version

*Task*: `services.packages.system.keepalived_version`

This test checks that the configured Keepalived package is installed on all nodes, has equal version and this version is 
recommended and corresponds with cluster.yaml.

###### 205 Audit Version

*Task*: `services.packages.system.audit_version`

This test checks that the configured Audit package is installed on all nodes, has equal version and this version is 
recommended and corresponds with cluster.yaml.

###### 205 Mandatory Package Versions

*Task*: `services.packages.system.mandatory_versions`

This test checks that the configured mandatory packages are installed on all nodes, has equal version and this version 
corresponds with cluster.yaml.

##### 206 Generic Packages Version

*Task*: `services.packages.generic.version`

This test checks that the configured generic packages are installed on all nodes, has equal version and this version 
corresponds with cluster.yaml.

##### 207 Pods Condition

*Task*: `kubernetes.pods`

This test checks that system pods are in good condition.

##### 208 Dashboard Availability

*Task*: `kubernetes.plugins.dashboard`

This test checks that the dashboard is available by its URL.

##### 209 Nodes Existence

*Task*: `kubernetes.nodes.existence`

This test checks for the presence of nodes in the Kubernetes cluster.

##### 210 Nodes Roles

*Task*: `kubernetes.nodes.roles`

This test checks the nodes' roles in the Kubernetes cluster.

##### 211 Nodes Condition

Tests of this type check the condition of the nodes that the Kubernetes reports.

###### 211 Nodes Condition - NetworkUnavailable

*Task*: `kubernetes.nodes.condition.network`

This test checks the condition `NetworkUnavailable` of the Kubernetes nodes of the cluster.

###### 211 Nodes Condition - MemoryPressure

*Task*: `kubernetes.nodes.condition.memory`

This test checks the condition `MemoryPressure` of the Kubernetes nodes of the cluster.

###### 211 Nodes Condition - DiskPressure

*Task*: `kubernetes.nodes.condition.disk`

This test checks the condition `DiskPressure` of the Kubernetes nodes of the cluster.

###### 211 Nodes Condition - PIDPressure

*Task*: `kubernetes.nodes.condition.pid`

This test checks the condition `PIDPressure` of the Kubernetes nodes of the cluster.

###### 211 Nodes Condition - Ready

*Task*: `kubernetes.nodes.condition.ready`

This test checks the condition `Ready` of the Kubernetes nodes of the cluster.

##### 212 Thirdparties Hashes

*Task*: `thirdparties.hashes`

This test checks that configured thirdparties hashes are equal to actual files hashes on nodes.

##### 213 Selinux Security Policy

*Task*: `services.security.selinux.status`

The test checks the status of Selinux. It must be `enforcing`. It may be `permissive`, but must be explicitly specified
in the inventory. Otherwise, the test will fail. This test is applicable only for systems of the RHEL family.

##### 214 Selinux Configuration

*Task*: `services.security.selinux.config`

The test compares the configuration of Selinux on the nodes with the configuration specified in the inventory or with the
one by default. If the configuration does not match, the test will fail.

##### 215 Firewalld Status

*Task*: `services.security.firewalld.status`

The test verifies that the FirewallD is disabled on cluster nodes, otherwise the test will fail.

##### 216 Swap State

*Task*: `services.system.swap.status`

The test verifies that swap is disabled on all nodes in the cluster, otherwise the test will fail.

##### 217 Modprobe Rules

*Task*: `services.system.modprobe.rules`

The test compares the modprobe rules on the nodes with the rules specified in the inventory or with default rules. If
rules does not match, the test will fail.

##### 218 Time Difference

*Task*: `services.system.time`

The test verifies that the time between all nodes does not differ by more than the maximum limit value. Otherwise, the 
cluster may not work properly and the test will be highlighted with a warning.

Maximum limit value: 15000ms

**Note:** this test can give a false-positive result if there are a lot of nodes in the cluster, there is too much delay
between the deployer node and all the others, or any other conditions of the environment. It is also recommended to be 
sure to perform latency tests: [002 Latency - Single Thread](#002-latency---single-thread) and 
[003 Latency - Multi Thread](#003-latency---multi-thread).

##### 219 Health Status ETCD

*Task*: `etcd.health_status`

This test verifies ETCD health.

##### 220 Control Plane Configuration Status

*Task*: `control_plane.configuration_status`

This test verifies the consistency of the configuration (image version, `extra_args`, `extra_volumes`) of static pods of Control Plain like `kube-apiserver`, `kube-controller-manager` and `kube-scheduler`.

##### 221 Control Plane Health Status

*Task*: `control_plane.health_status`

This test verifies the health of static pods `kube-apiserver`, `kube-controller-manager` and `kube-scheduler`.

##### 222 Default Services Configuration Status

*Task*: `default_services.configuration_status`

In this test, the versions of the images of the default services, such as `kube-proxy`, `coredns`,
`calico-node`, `calico-kube-controllers`, `calico-apiserver` and `ingress-nginx-controller` are checked,
and the `coredns` configmap is also checked.

##### 223 Default Services Health Status

*Task*: `default_services.health_status`

This test verifies the health of `kube-proxy`, `coredns`,
`calico-node`, `calico-kube-controllers`, `calico-apiserver`, and `ingress-nginx-controller` pods.

##### 224 Calico Configuration Check

*Task*: `calico.config_check`

This test checks the configuration of the `calico-node` envs, Calico's ConfigMap in case of `ipam`, and also performed `calicoctl ipam check`.

###### 230 Calico API Server Health Status

*Task*: `calico.apiserver.health_status`

This test verifies the Calico API server health.

##### 225 Pod Security Admission Status

*Task*: `kubernetes.admission`

The test checks status of Pod Security Admissions, default PSS (Pod Security Standards) profile and match consistence between 'cluster.yaml' and current Kubernetes configuration. Also it check consistency between 'kube-apiserver.yaml' and 'kubeadm-config'.

##### 226 Geo Connectivity Status

*Task*: `geo_check`

The task checks the status of DNS resolving, pod-to-service, and pod-to-pod connectivity between clusters in geographically
distributed schemas. This task works only if procedure config file is provided with information about `paas-geo-monitor`,
at least service name and namespace. For example:
```yaml
geo-monitor:
  namespace: site-manager
  service: paas-geo-monitor
```

For more information about `paas-geo-monitor` service, refer to DRNavigator repository.

##### 227 AppArmor Status

*Task*: `services.security.apparmor.status`

The test checks the status of AppArmor. It should be `enabled` by default.

##### 228 AppArmor Configuration

*Task*: `services.security.apparmor.config`

The test checks the AppArmor configuration. It has several modes: `enforce`, `complain`, and `disable`. The profiles (resources) stick to one of the modes. The `cluster.yaml` may include only part of the profiles.

##### 229 Audit Policy Configuration

*Task*: `kubernetes.audit.policy`

This test checks that the configuration of Kubernetes audit policy is actual
and matches the effectively resolved configuration from the inventory.

##### 231 Audit Daemon Rules

*Task*: `system.audit.rules`

This test compares the Audit rules on the nodes
with the rules specified in the inventory or with the default rules.
If the configured rules are not presented, the test fails.

##### 232 Kernel Parameters Configuration

*Task*: `system.sysctl.config`

This test compares the kernel parameters on the nodes
with the parameters specified in the inventory or with the default parameters.
If the configured parameters are not presented, the test fails.

### Report File Generation

In addition to the resulting table in the log output, the same report is presented in the form of files.

#### HTML Report

The report allows you to visually see the final report. All content, including styles, is already included inside a single file. You can use the following supported command line arguments:

|Argument|Default|Description|
|---|---|---|
|**--html-report**|`report.html`|The full absolute path to the file location where the report is saved.|
|**--disable-html-report**| |If specified, the report generation is disabled.|

Report file example (trimmed):

```html
<!DOCTYPE html>
<html>
	<head>
		<meta charset="utf-8">
		<title>PAAS Check Report</title>
	</head>
	<body>
		<div id="date">2020-04-29 10:09:31.096773</div>
		<div id="stats">
			<div class="succeeded">12 succeeded</div>
		</div>
		<h1>PAAS Check Report</h1>
		<table>
			<thead>
				<tr>
					<td>Group</td>
					<td>Status</td>
					<td>ID</td>
					<td>Test</td>
					<td>Actual Result</td>
					<td>Minimal</td>
					<td>Recommended</td>
				</tr>
			</thead>
			<tbody>
				<tr class="ok">
					<td>services</td>
					<td>
						<div>ok</div>
					</td>
					<td>201</td>
					<td>Haproxy Status</td>
					<td>active (running)</td>
					<td></td>
					<td></td>
				</tr>
				<tr class="ok">
					<td>services</td>
					<td>
						<div>ok</div>
					</td>
					<td>201</td>
					<td>Keepalived Status</td>
					<td>active (running)</td>
					<td></td>
					<td></td>
				</tr>
				<tr class="ok">
					<td>services</td>
					<td>
						<div>ok</div>
					</td>
					<td>201</td>
					<td>Docker Status</td>
					<td>active (running)</td>
					<td></td>
					<td></td>
				</tr>
			</tbody>
		</table>
	</body>
</html>
```

#### CSV Report

This report allows a thirdparty software to parse the report result. This is convenient when working with Excel or automatic metrics collection systems. You can use the following supported command line arguments:

|Argument|Default|Description|
|---|---|---|
|**--csv-report**|`report.csv`|The full absolute path to the file location where the report is saved.|
|**--csv-report-delimiter**|`;`|The character used as a column separator.|
|**--disable-csv-report**| |If specified, the report generation is disabled.|

Report file example:

```csv
group;status;test_id;test_name;current_result;minimal_result;recommended_result
services;ok;201;Haproxy Status;active (running);;
services;ok;201;Keepalived Status;active (running);;
services;ok;201;Docker Status;active (running);;
services;ok;201;Kubelet Status;active (running);;
kubernetes;ok;202;Kubelet Version;v1.16.3;;
kubernetes;ok;203;Nodes Existence;All nodes presented;;
kubernetes;ok;204;Nodes Roles;All nodes have the correct roles;;
kubernetes;ok;205;Nodes Condition - NetworkUnavailable;CalicoIsUp;;
kubernetes;ok;205;Nodes Condition - MemoryPressure;KubeletHasSufficientMemory;;
kubernetes;ok;205;Nodes Condition - DiskPressure;KubeletHasNoDiskPressure;;
kubernetes;ok;205;Nodes Condition - PIDPressure;KubeletHasSufficientPID;;
kubernetes;ok;205;Nodes Condition - Ready;KubeletReady;;
```
