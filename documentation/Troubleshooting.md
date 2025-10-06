<!-- #GFCFilterMarkerStart# -->
# Kubemarine and Kubernetes Troubleshooting Guide
<!-- #GFCFilterMarkerEnd# -->

This section provides troubleshooting information for Kubemarine and Kubernetes solutions.

- [Kubemarine Errors](#kubemarine-errors)
  - [KME0001: Unexpected exception](#kme0001-unexpected-exception)
  - [KME0002: Remote group exception](#kme0002-remote-group-exception)
    - [Command did not complete within a number of seconds](#command-did-not-complete-within-a-number-of-seconds)
  - [KME0004: There are no control planes defined in the cluster scheme](#kme0004-there-are-no-control-planes-defined-in-the-cluster-scheme)
  - [KME0005: {hostnames} are not sudoers](#kme0005-hostnames-are-not-sudoers)
  - [KME0006: Node Accessibility Issues](#kme0006-node-accessibility-issues)
  - [KME0008: Invalid Kubernetes Version](#kme0008-invalid-kubernetes-version)
  - [KME0009: Redefined Key in Plugin Configuration](#kme0009-redefined-key-in-plugin-configuration)
  - [KME0010: Redefined Associations in Package Configuration](#kme0010-redefined-associations-in-package-configuration)
  - [KME0011: Redefined Key in Third-Party Configuration](#kme0011-redefined-key-in-third-party-configuration)
  - [KME0012: Procedure Restricted by OS Family Compatibility](#kme0012-procedure-restricted-by-os-family-compatibility)
  - [KME0013: Redefined Key in Containerd Configuration](#kme0013-redefined-key-in-containerd-configuration)
  - [KME0014: Invalid Helm Chart URL](#kme0014-invalid-helm-chart-url)
- [Troubleshooting Tools](#troubleshooting-tools)
  - [etcdctl Script](#etcdctl-script)
  - [etcdutl binary](#etcdutl-binary)
- [Troubleshooting Kubernetes Generic Issues](#troubleshooting-kubernetes-generic-issues)
  - [CoreDNS Responds With High Latency](#coredns-responds-with-high-latency)
  - [Namespace With Terminating CR/CRD Cannot Be Deleted. Terminating CR/CRD Cannot Be Deleted](#namespace-with-terminating-crcrd-cannot-be-deleted-terminating-crcrd-cannot-be-deleted)
  - [Packets Between Nodes in Different Networks Are Lost](#packets-between-nodes-in-different-networks-are-lost)
  - [`kubectl apply` Fails With Error "metadata annotations: Too long"](#kubectl-apply-fails-with-error-metadata-annotations-too-long)
  - [`kube-apiserver` Requests Throttling](#kube-apiserver-requests-throttling)
  - [Long Recovery After a Node Goes Offline](#long-recovery-after-a-node-goes-offline)
  - [`kube-controller-manager` Unable to Sync Caches for Garbage Collector](#kube-controller-manager-unable-to-sync-caches-for-garbage-collector)
  - [Etcdctl Compaction and Defragmentation](#etcdctl-compaction-and-defragmentation)
  - [Etcdctl Defrag Return Context Deadline Exceeded](#etcdctl-defrag-return-context-deadline-exceeded)
  - [Etcdserver Request Timeout](#etcdserver-request-timeout)
  - [Etcd Database Corruption](#etcd-database-corruption)
    - [Manual Restoration of Etcd Database](#manual-restoration-of-etcd-database)
  - [HTTPS Ingress Doesn't Work](#https-ingress-doesnt-work)
  - [Garbage Collector Does Not Initialize If Convert Webhook Is Broken](#garbage-collector-does-not-initialize-if-convert-webhook-is-broken)
  - [Pods Stuck in "terminating" Status During Deletion](#pods-stuck-in-terminating-status-during-deletion)
  - [Random 504 Error on Ingresses](#random-504-error-on-ingresses)
  - [Nodes Have `NotReady` Status Periodically](#nodes-have-notready-status-periodically)
  - [Long Pulling of Images](#long-pulling-of-images)
  - [No Pod-to-Pod Traffic for Some Nodes with More Than One Network Interface](#no-pod-to-pod-traffic-for-some-nodes-with-more-than-one-network-interface)
  - [No Pod-to-Pod Traffic for Some Nodes with More Than One IPs with Different CIDR Notation](#no-pod-to-pod-traffic-for-some-nodes-with-more-than-one-ips-with-different-cidr-notation)
  - [Ingress Cannot Be Created or Updated](#ingress-cannot-be-created-or-updated)
  - [vIP Address is Unreachable](#vip-address-is-unreachable)
  - [CoreDNS Cannot Resolve the Name](#coredns-cannot-resolve-the-name)
    - [Case 1](#case-1)
    - [Case 2](#case-2)
  - [Calico Generates High Amount of Logs and Consumes a lot of CPU](#calico-generates-high-amount-of-logs-and-consumes-a-lot-of-cpu) 
  - [Calico 3.29.0 Leading to kubernetes Controller Manager GC Failures](#calico-3290-leading-to-kubernetes-controller-manager-gc-failures) 
- [Troubleshooting Kubemarine](#troubleshooting-kubemarine)
  - [Operation not Permitted Error in Kubemarine Docker Run](#operation-not-permitted-error-in-kubemarine-docker-run)
  - [Failures During Kubernetes Upgrade Procedure](#failures-during-kubernetes-upgrade-procedure)
  - [Numerous Generation of Auditd System Messages](#numerous-generation-of-auditd-system)
  - [Failure During Installation on Ubuntu OS With Cloud-init](#failure-during-installation-on-ubuntu-os-with-cloud-init)
  - [Troubleshooting an Installation That Ended Incorrectly](#troubleshooting-an-installation-that-ended-incorrectly)
  - [Upgrade Procedure to v1.28.3 Fails on ETCD Step](#upgrade-procedure-to-v1283-fails-on-etcd-step)
  - [kubectl logs and kubectl exec fail](#kubectl-logs-and-kubectl-exec-fail)
  - [OpenSSH server becomes unavailable during cluster installation on Centos 9](#openssh-server-becomes-unavailable-during-cluster-installation-on-centos-9)
  - [Packets Loss During the Transmission Between Nodes](#packets-loss-during-the-transmission-between-nodes)

# Kubemarine Errors

This section lists all known errors with explanations and recommendations for their fixing. If an 
error occurs during the execution of any of these procedures, you can find it here.

## KME0001: Unexpected exception

### Description
This error occurs when an unexpected exception is encountered during runtime and has not yet been assigned a classifying code.

### Alerts
- **Alert:** TASK FAILED - `KME001: Unexpected exception`

### Stack trace(s)
```text
FAILURE - TASK FAILED xxx
Reason: KME001: Unexpected exception
Traceback (most recent call last):
  File "/home/centos/repos/kubemarine/kubemarine/src/core/flow.py", line 131, in run_flow
    task(cluster)
  File "/home/centos/repos/kubemarine/kubemarine/install", line 193, in deploy_kubernetes_init
    cluster.nodes["worker"].new_group(apply_filter=lambda node: 'control-plane' not in node['roles']).call(kubernetes.init_workers)
  File "/home/centos/repos/kubemarine/kubemarine/src/core/group.py", line 165, in call
    return self.call_batch([action], **{action.__name__: kwargs})
  File "/home/centos/repos/kubemarine/kubemarine/src/core/group.py", line 179, in call_batch
    results[action] = action(self, **action_kwargs)
  File "/home/centos/repos/kubemarine/kubemarine/src/kubernetes.py", line 238, in init_workers
    reset_installation_env(group)
  File "/home/centos/repos/kubemarine/kubemarine/src/kubernetes.py", line 60, in reset_installation_env
    group.sudo("systemctl stop kubelet", warn=True)
  File "/home/centos/repos/kubemarine/kubemarine/src/core/group.py", line 34, in sudo
    return self.do("sudo", *args, **kwargs)
  File "/home/centos/repos/kubemarine/kubemarine/src/core/group.py", line 106, in do
    self.workaround(exception)
  File "/home/centos/repos/kubemarine/kubemarine/src/core/group.py", line 119, in workaround
    raise e from None
  File "/home/centos/repos/kubemarine/kubemarine/src/core/group.py", line 95, in do
    return self._do(do_type, args, kwargs)
  File "/home/centos/repos/kubemarine/kubemarine/src/core/group.py", line 141, in _do
    with ThreadPoolExecutor(max_workers=len(self.nodes)) as executor:
  File "/usr/lib/python3.6/concurrent/futures/thread.py", line 104, in __init__
    raise ValueError("max_workers must be greater than 0")
ValueError: max_workers must be greater than 0
```

### How to resolve
1. Run the [IAAS checker](Kubecheck.md#iaas-procedure) and [PAAS checker](Kubecheck.md#paas-procedure) to identify potential issues with the nodes or the cluster.
2. If the checker reports failed tests, fix the cause of the failure and rerun the task.
3. Adjust the number of workers to ensure `max_workers` is greater than 0.
4. If you are unable to resolve the issue, [start a new issue](https://github.com/Netcracker/KubeMarine/issues/new) and provide the error details along with the stack trace for further assistance.

### Recommendations
To avoid this issue in the future:
- Validate the cluster's node configuration before deployment to ensure the number of workers is correctly set.
- Regularly check the system's configuration and update it as necessary.

>**Note**  
>If you resolve the problem, consider [opening a new PR](https://github.com/Netcracker/KubeMarine/pulls) to document your solution, Our team will appreciate it!


## KME0002: Remote group exception

### Description
This error occurs when a bash command executed on a remote cluster host terminates unexpectedly with a non-zero exit code. In this case, the command `'apt install bad-package-name'` failed with exit code 127, indicating that the `apt` command was not found on the remote node.

### Alerts
Not applicable.

### Stack trace(s)
```text
FAILURE!
TASK FAILED xxx
KME0002: Remote group exception
10.101.10.1:
  Encountered a bad command exit code!
  
  Command: 'apt install bad-package-name'
  
  Exit code: 127
  
  === stderr ===
  bash: apt: command not found
```

### How to resolve
1. Run the [IAAS checker](Kubecheck.md#iaas-procedure) and [PAAS checker](Kubecheck.md#paas-procedure) to ensure that the infrastructure and platform are functioning properly.
2. Inspect the node where the error occurred. In our particular example, it is required to check the presence of the required package manager and install it if it is missing. 
3. Verify that all necessary dependencies are correctly installed on the node, and reattempt the task.
4. Ensure that the inventory and configuration files are correctly set up, following the proper sequence of commands.
5. If the issue persists, [start a new issue](https://github.com/Netcracker/KubeMarine/issues/new) and provide a description of the error with its stack trace for further assistance.

### Recommendations
To avoid this issue in the future:
- Validate the remote node’s environment to ensure that the required package management tools are available before running any package installation commands.
- Always verify the compatibility of commands with the system type (e.g., Debian vs. RHEL-based distributions).

>**Note**  
>If you resolve the problem, consider [opening a new PR](https://github.com/Netcracker/KubeMarine/pulls) to document your solution, which will help others in the community.

## Command did not complete within a number of seconds

### Description
This error occurs when a command does not complete within the allowed execution time of 2700 seconds (45 minutes). In the provided example, the command `'echo "sleeping..." && sleep 3000'` exceeded the timeout, causing the task to fail. This issue could arise due to a hanging command, a problem with the remote hypervisor, or network issues between the deployer node and the cluster.

### Alerts
Not applicable.

### Stack trace(s)
```text
FAILURE!
TASK FAILED xxx
KME0002: Remote group exception
10.101.10.1:
  Command did not complete within 2700 seconds!
  
  Command: 'echo "sleeping..." && sleep 3000'
  
  === stdout ===
  sleeping...
```

### How to resolve
1. Inspect the remote node for potential issues causing the hang. This could include a malfunctioning hypervisor or a hung process.
2. Reboot the hypervisor or node if it is not responding, or manually terminate any hanging processes.
3. Check for SSH connectivity issues between the deployer node and the cluster, and verify the network stability.
4. Investigate the environment or settings of the executable command for any misconfigurations or issues causing the prolonged execution.
5. Run the [IAAS checker](Kubecheck.md#iaas-procedure) to detect any network connectivity issues between the nodes.
6. If the problem persists, update the executable or make other environment changes to resolve the hanging command.

### Recommendations
To prevent this issue in the future:
- Ensure that time-sensitive commands are optimized to complete within the allowed time limit.
- Regularly monitor the network connection between the deployer and cluster nodes to identify and resolve any latency or connectivity issues early.
- Configure appropriate timeout settings for long-running commands to avoid task failures.

>**Note**  
>If you resolve the problem, consider [opening a new PR](https://github.com/Netcracker/KubeMarine/pulls) to document your solution, which will help others in the community.


## KME0004: There are no control planes defined in the cluster scheme

### Description
This error occurs when there are no nodes with the `control-plane` role defined in the cluster's inventory file. The error happens before the payload is executed on the cluster, indicating a misconfiguration in the cluster setup.

### Alerts
Not applicable.

### Stack trace(s)
```text
FAILURE!
KME0004: There are no control planes defined in the cluster scheme
```

### How to resolve
1. Check the cluster's inventory file to ensure that there is at least one node assigned with the `control-plane` role.
2. If no control plane nodes are defined, add new nodes with the `control-plane` role to the cluster inventory. 
   
   Example of defining separate control-plane and worker nodes:
   ```yaml
   - address: 10.101.1.1
     internal_address: 192.168.101.1
     name: control-plane-1
     roles:
     - control-plane
   - address: 10.101.1.2
     internal_address: 192.168.101.2
     name: worker-1
     roles:
     - worker
   ```
3. Alternatively, you can assign both the `control-plane` and `worker` roles to existing worker nodes.

   Example of a node with both control-plane and worker roles:
   ```yaml
   - address: 10.101.1.1
     internal_address: 192.168.101.1
     name: control-plane-1
     roles:
     - control-plane
     - worker
   ```
4. Once the roles are properly configured, reapply the changes and rerun the task.

### Recommendations
To avoid this issue in the future:
- Double-check the inventory file to ensure the correct roles are assigned to nodes, particularly ensuring there is always at least one control-plane node.
- For environments where nodes serve both control-plane and worker roles, monitor their resource usage to avoid overloading them.

>**Note**  
>Control-planes with a worker role remain as control planes, however, they start scheduling applications pods.


## KME0005: {hostnames} are not sudoers

### Description
This error occurs when the connection users on the specified nodes do not have superuser (sudo) privileges or are required to enter a password to run `sudo` commands. The error is raised before the payload is executed on the cluster, typically during the `install` or `add_node` procedures.

### Alerts
Not applicable.

### Stack trace(s)
```text
FAILURE!
TASK FAILED prepare.check.sudoer
KME0005: ['10.101.1.1'] are not sudoers
```

### How to resolve
1. Add the connection user to the sudoers group on the affected cluster nodes. For example, on Ubuntu, use the following command (note that a reboot is required):
   ```bash
   sudo adduser <username> sudo
   ```
2. To allow the connection user to run `sudo` commands without requiring a password, edit the `/etc/sudoers` file and add the following line at the end:
   ```bash
   username  ALL=(ALL) NOPASSWD:ALL
   ```
   Replace `username` with the actual username of the connection user.
3. Reboot the affected nodes and verify that the user has the required sudo privileges.
4. Retry the `install` or `add_node` procedure.

### Recommendations
To prevent this issue in the future:
- Ensure all connection users are properly configured with sudo privileges on all nodes before running any procedures.
- Regularly audit the sudoer configurations to avoid permission issues during deployments or node additions.

## KME0006: Node Accessibility Issues

### Description
This error occurs when nodes are either offline or inaccessible through SSH during the cluster setup or runtime operations.

### Alerts
- **Alert:** Nodes not reachable or inaccessible through SSH.

### Stack trace(s)
Not applicable.

### How to resolve
1. For nodes reported as **offline**:
   - Verify that the node addresses are correctly entered in the inventory.
   - Ensure the nodes are powered on and reachable over the network.
   - Check that the SSH port is open and correctly configured.
   - Confirm that the SSH daemon is running and properly set up on the nodes.

2. For nodes reported as **inaccessible**:
   - Validate that the SSH credentials (keyfile, username, password) are correct in the inventory.
   - Test the SSH connection manually to confirm access.

### Recommendations
- Test connectivity to all nodes using ping and SSH before initiating any cluster setup or updates.

>**Note**  
>If you resolve the problem, consider [opening a new PR](https://github.com/Netcracker/KubeMarine/pulls) to document your solution, which will help others in the community.


## KME0008: Invalid Kubernetes Version

### Description
This error occurs when a specified Kubernetes version is not allowed for use. The selected version does not match the list of supported or allowed versions.

### Alerts
- **Alert:** Specified Kubernetes version is invalid or unsupported.

### Stack trace(s)
Not applicable.

### How to resolve
1. Verify the Kubernetes version specified in your configuration.
2. Check the list of allowed versions provided in the error message: `{allowed_versions}`.
3. Update your configuration to use one of the allowed Kubernetes versions.
4. Re-run the task or setup process after correcting the version.

### Recommendations
- Before starting the setup, always refer to the official documentation or project configuration to identify supported Kubernetes versions.

>**Note**  
>If you resolve the problem, consider [opening a new PR](https://github.com/Netcracker/KubeMarine/pulls) to document your solution, which will help others in the community.


## KME0009: Redefined Key in Plugin Configuration

### Description
This error occurs when a key in the plugin configuration is redefined in the `cluster.yaml` file but is missing in the procedure inventory. The mismatch indicates that the required plugin configuration is not explicitly specified in the procedure inventory.

### Alerts
- **Alert:** Key redefined in `cluster.yaml` but missing in the procedure inventory.

### Stack trace(s)
Not applicable.

### How to resolve
1. Identify the key in question.
2. Verify the plugin name.
3. Check the `cluster.yaml` file for the redefined key and review the changes in the procedure.yaml
4. Update the procedure inventory to include the required plugin configuration explicitly.
5. Re-run the process after ensuring consistency between the `cluster.yaml` and procedure.yaml files.

### Recommendations
- Maintain a consistent plugin configuration between `cluster.yaml` and the procedure inventory files.
- Before making changes, review the plugin configuration schema and ensure all required keys are explicitly defined in both files.

>**Note**  
>If you resolve the problem, consider [opening a new PR](https://github.com/Netcracker/KubeMarine/pulls) to document your solution, which will help others in the community.

## KME0010: Redefined Associations in Package Configuration

### Description
This error occurs when associations for a package are redefined in the `cluster.yaml` file but are missing in the procedure inventory. The inconsistency indicates that the required associations are not explicitly specified in the procedure inventory.

### Alerts
- **Alert:** Associations redefined in `cluster.yaml` but missing in the procedure inventory.

### Stack trace(s)
Not applicable.

### How to resolve
1. Identify the package in question.
2. Check the `cluster.yaml` file for the redefined associations and review the changes in the procedure.yaml
3. Update the procedure inventory to include the required associations explicitly for the package.
4. Ensure the associations are consistent between the `cluster.yaml` and procedure inventory files.
5. Re-run the process after making the necessary updates.

### Recommendations
- Always maintain consistency in package associations between `cluster.yaml` and procedure inventory files.
- Regularly validate that all required associations are explicitly defined in the procedure inventory.

>**Note**  
>If you resolve the problem, consider [opening a new PR](https://github.com/Netcracker/KubeMarine/pulls) to document your solution, which will help others in the community.


## KME0011: Redefined Key in Third-Party Configuration

### Description
This error occurs when a key in the third-party configuration is redefined in the `cluster.yaml` file but is missing in the procedure inventory. This inconsistency indicates that the required third-party configuration is not explicitly specified in the procedure inventory.

### Alerts
- **Alert:** Key redefined in `cluster.yaml` for a third-party component but missing in the procedure inventory.

### Stack trace(s)
Not applicable.

### How to resolve
1. Identify the key in question.
2. Verify the third-party component name.
3. Check the `cluster.yaml` file for the redefined key and review the changes in the procedure.yaml
4. Update the procedure inventory to include the required third-party configuration explicitly.
5. Ensure consistency between the `cluster.yaml` and procedure inventory files for the third-party configuration.
6. Re-run the process after making the necessary updates.

### Recommendations
- Always ensure that third-party configurations are explicitly defined in the procedure inventory to avoid inconsistencies.
- Regularly validate third-party configurations between `cluster.yaml` and procedure inventory files.

>**Note**  
>If you resolve the problem, consider [opening a new PR](https://github.com/Netcracker/KubeMarine/pulls) to document your solution, which will help others in the community.

## KME0012: Procedure Restricted by OS Family Compatibility

### Description
This error occurs when a procedure is attempted on a cluster where nodes do not all share the same and supported OS family. The procedure requires uniformity in the OS family across all nodes in the cluster.

### Alerts
- **Alert:** Procedure is not possible due to incompatible OS families across cluster nodes.

### Stack trace(s)
Not applicable.

### How to resolve
1. Verify the OS family of each node in the cluster.
   - Ensure all nodes have the same OS family.
   - Confirm that the OS family is supported for the procedure.
2. Update the nodes to use a consistent and supported OS family.
3. Retry the procedure after ensuring OS family uniformity.

### Recommendations
- Standardize the OS family across all nodes in the cluster before starting any procedure to avoid compatibility issues.

>**Note**  
>If you resolve the problem, consider [opening a new PR](https://github.com/Netcracker/KubeMarine/pulls) to document your solution, which will help others in the community.


## KME0013: Redefined Key in Containerd Configuration

### Description
This error occurs when the `sandbox_image` key for the `containerdConfig` plugin is redefined in the `cluster.yaml` file but is missing in the procedure inventory. This indicates that the required `sandbox_image` configuration is not explicitly specified in the procedure inventory.

### Alerts
- **Alert:** Key `'plugins."io.containerd.grpc.v1.cri".sandbox_image'` redefined in `cluster.yaml` but missing in procedure inventory.

### Stack trace(s)
Not applicable.

### How to resolve
1. Identify the key in question: `'plugins."io.containerd.grpc.v1.cri".sandbox_image'`.
2. Verify the plugin configuration for `containerdConfig` in the `cluster.yaml` file.
3. Update the procedure inventory to explicitly include the `sandbox_image` key for the `containerdConfig` plugin.
4. Ensure consistency between the `cluster.yaml` and procedure inventory files for the `sandbox_image` configuration.
5. Re-run the process after making the necessary updates.

### Recommendations
- Ensure that all necessary keys, including `sandbox_image`, are explicitly defined in the procedure inventory to avoid configuration issues.

>**Note**  
>If you resolve the problem, consider [opening a new PR](https://github.com/Netcracker/KubeMarine/pulls) to document your solution, which will help others in the community.

## KME0014: Invalid Helm Chart URL

### Description
This error occurs when the provided Helm chart URL does not return the expected content type in the specified file. If the URL is pointing to a private repository, the correct authentication may be missing.

### Alerts
- **Alert:** Helm chart URL does not return the expected content.

### Stack trace(s)
Not applicable.

### How to resolve
1. Verify the Helm chart URL.
2. Ensure the URL returns the correct content type in the file located at destination.
3. If the repository is private, check that the correct authentication (such as a token or credentials) is provided.
4. Test the URL manually to confirm it is accessible and returning the expected content.
5. Re-run the procedure after validating the URL and authentication.

### Recommendations
- Always verify the Helm chart URL before using it in your configuration.
- Ensure proper authentication is provided for private repositories to avoid access issues.

>**Note**  
>If you resolve the problem, consider [opening a new PR](https://github.com/Netcracker/KubeMarine/pulls) to document your solution, which will help others in the community.

# Troubleshooting Tools

This section describes the additional tools that Kubemarine provides for convenient troubleshooting of various issues.

## Etcdctl Script

This script allows you to execute `etcdctl` queries without installing an additional binary file and setting up a connection. This file is installed during the `prepare.thirdparties` installation task on all control-planes and requires root privileges.

To execute a command through this script, make sure you meet all the following prerequisites:

* You run the command from the control-plane node with root privileges.
* You have configured `admin.conf` on node.
* The node with which you are running has all the necessary ETCD certificates and they are located in the correct paths.

If all prerequisites are achieved, you can execute almost any `etcdctl` command.
For example:

```
# etcdctl member list
# etcdctl endpoint health --cluster -w table
# etcdctl endpoint status --cluster -w table
```

To find out all the available `etcdctl` options and features, use the original ETCD documentation.

To execute the command, the script tries to launch the container using the following algorithm:

1. Detect already running ETCD in Kubernetes cluster, parse its parameters, and launch the ETCD container with the same parameters on the current node.
2. If the Kubernetes cluster is dead, then try to parse the `/etc/kubernetes/manifests/etcd.yaml` file and launch the ETCD container.

Since the command is run from a container, this imposes certain restrictions. For example, only certain volumes are mounted to the container. Which one it is, depends directly on the version and type of installation of ETCD and Kubernetes, but as a rule it is:

* `/var/lib/etcd`:`/var/lib/etcd`
* `/etc/kubernetes/pki`:`/etc/kubernetes/pki`

## Etcdutl binary

Starting with etcd v3.6, in addition to `etcdctl` script, there is a new `etcdutl` binary, which took some responsibility from `etcdctl`. This binary is installed during the `prepare.thirdparties` installation task on all control-planes and requires root privileges.

To find out all the available `etcdutl` options and features, use the original ETCD documentation, for example:
* [Disaster recovery](https://etcd.io/docs/v3.6/op-guide/recovery/)
* [etcdutl README.md](https://github.com/etcd-io/etcd/tree/release-3.6/etcdutl)

# Troubleshooting Kubernetes Generic Issues

This section provides troubleshooting information for generic Kubernetes solution issues, which are not specific to Kubemarine installation.

## CoreDNS Responds With High Latency

### Description
CoreDNS may respond with delays when there is a high load due to a large volume of applications or nodes in the cluster. This increased load can cause CoreDNS to slow down its response times.

### Stack trace(s)
Not applicable.

### How to resolve
1. Increase the number of CoreDNS replicas to handle the higher load. Use the following command to scale up the replicas:
   ```bash
   kubectl scale deployments.apps -n kube-system coredns --replicas=4
   ```
   You can choose the number of replicas based on the cluster's size and load.
2. Additionally, configure anti-affinity rules to ensure that all CoreDNS pods are distributed across different nodes without duplicates. This helps prevent overloading individual nodes.

### Recommendations
To avoid high latency in CoreDNS in the future:
- Monitor the load on CoreDNS regularly and adjust the number of replicas as needed.
- Use anti-affinity rules to distribute CoreDNS pods evenly across the cluster to balance the load.

>**Note**  
>Not applicable.

## Namespace With Terminating CR/CRD Cannot Be Deleted. Terminating CR/CRD Cannot Be Deleted

### Description
A namespace containing a terminating CustomResource cannot be deleted, or simply CustomResource in some namespace hangs infinitely in the terminating status and cannot be deleted. 

### Alerts
Not applicable.

### Stack trace(s)
Not applicable.

### How to resolve
The issue occurs due to the presence of non-deleted finalizers in the `CustomResource`. These finalizers prevent the resource from being deleted, typically because the controller responsible for managing the `CustomResource` is not operational (e.g., if the controller is deleted or unavailable).

There are two potential solutions:

1. **Restart the Controller:**
   - If the controller is temporarily unavailable, the `CustomResource` will be deleted once the controller becomes operational again. This is the recommended solution since it allows the controller to execute the required on-delete logic for the `CustomResource`.
   
2. **Manually Remove Finalizers:**
   - If the controller has been permanently removed or is not desired, you can manually delete the finalizers from the `CustomResource`. However, this is not recommended as it bypasses the on-delete logic typically handled by the controller.

To manually remove finalizers, execute the following command:
```bash
kubectl patch <cr-singular-alias/cr-name> -p '{"metadata":{"finalizers":[]}}' --type=merge
```
For example:
```bash
kubectl patch crontab/my-new-cron-object -p '{"metadata":{"finalizers":[]}}' --type=merge
```

### Recommendations
To avoid this issue in the future:
- Ensure that controllers managing `CustomResources` are kept operational and healthy to handle resource finalization.
- Avoid manually deleting finalizers unless absolutely necessary, as this skips important cleanup logic provided by the controller.

>**Note**  
>CustomResources with non-empty finalizers are never deleted.


## Packets Between Nodes in Different Networks Are Lost

### Description
Some packets between pods running on nodes in different networks are lost, including DNS requests on the network. This issue affects communication between pods across different networks.

### Alerts
Not applicable.

### Stack trace(s)
Not applicable.

### How to resolve
The default Kubernetes installation uses the Calico network plugin with IP-in-IP (ipip) mode set to CrossSubnet. In this configuration, packets between pods on nodes in the same network are sent directly, but packets between pods on nodes in different networks are routed through a tunnel. According to the [Calico documentation](https://docs.projectcalico.org/networking/mtu), the MTU on Calico tunnel interfaces should be 20 bytes less than the MTU on the main network interface.

To adjust the MTU size, run the following command on any control-plane node:

```bash
kubectl patch configmap/calico-config -n kube-system --type merge -p '{"data":{"veth_mtu": "1430"}}'
```

Where:
  - **1430** is the size of the MTU. For example, if the MTU on `eth0` is 1450, you should set the Calico MTU size to 1430.

After updating the ConfigMap, perform a rolling restart of all `calico/node` pods to apply the changes:

```bash
kubectl rollout restart daemonset calico-node -n kube-system
```

This change only affects new pods. To apply the new MTU value to all pods in the cluster, you must either restart all pods or reboot the nodes one by one.

### Recommendations
To avoid packet loss in the future:
- Ensure that the MTU size is correctly configured for the Calico tunnel interfaces to match the main network interface, with a 20-byte reduction as per the Calico documentation.
- Regularly monitor the network performance between nodes in different networks and make adjustments as needed.

>**Note**  
>If the MTU values are updated, be sure to restart all pods or nodes to ensure the new settings take effect across the cluster.

## `kubectl apply` Fails With Error "metadata annotations: Too long"

### Description
The `kubectl apply` command fails with the error message "metadata annotations: Too long" when trying to apply a resource with a very large configuration. This prevents the resource from being successfully applied.

### Alerts
Not applicable.

### Stack trace(s)
Not applicable.

### How to resolve
This issue occurs when you attempt to apply a resource with a large configuration. The error happens because `kubectl apply` tries to save the new configuration to the `kubectl.kubernetes.io/last-applied-configuration` annotation. If the new configuration is too large, it exceeds the annotation's size limit, and `kubectl apply` cannot proceed. The maximum size of annotations cannot be changed, so large resources cannot be applied using `kubectl apply`.

To resolve this issue, use `kubectl create` instead of `kubectl apply` for large resources.

### Recommendations
To avoid this issue in the future:
- Use `kubectl create` for resources with large configurations, as it bypasses the size limit on annotations.
- Break down large resource configurations into smaller, more manageable parts if possible, to prevent exceeding the annotation limit.

>**Note**  
>The maximum size for annotations is fixed and cannot be modified.

## `kube-apiserver` Requests Throttling

### Description
Different services may start receiving “429 Too Many Requests” HTTP errors, even though the `kube-apiserver` can handle more load. This issue occurs when the request rate limits for the `kube-apiserver` are too low, leading to throttling of requests.

### Alerts
Not applicable.

### Stack trace(s)
Not applicable.

### How to resolve
The root cause of this issue is the low rate limit for the `kube-apiserver`. To fix it, increase the rate limits by adjusting the `--max-requests-inflight` and `--max-mutating-requests-inflight` options in the `kube-apiserver` configuration:
- `--max-requests-inflight`: Defines the maximum number of non-mutating requests. The default value is 400.
- `--max-mutating-requests-inflight`: Defines the maximum number of mutating requests. The default value is 200.

Follow these steps to increase the rate limits:
1. Modify the `kube-apiserver` configuration file, which is located at `/etc/kubernetes/manifests/kube-apiserver.yaml` on all control-plane nodes.
2. Update the `kubeadm-config` ConfigMap in the `kube-system` namespace to ensure that the values match in the `apiServer` section.

Example configuration:
```yaml
apiVersion: v1
data:
  ClusterConfiguration: |
    apiServer:
      ...
      extraArgs:
        ...
        max-requests-inflight: "400"
        max-mutating-requests-inflight: "200"
        ...
```

### Recommendations
To avoid request throttling issues in the future:
- Regularly monitor the load on the `kube-apiserver` and adjust the rate limits accordingly.
- Ensure that rate limit settings are consistent across all control-plane nodes and in the `kubeadm-config` ConfigMap.

>**Note**  
>Be sure to apply these changes on all control-plane nodes for consistency.


## Long Recovery After a Node Goes Offline

### Description
When a cluster node goes offline, it may take up to 6 minutes for the pods running on that node to be redeployed to healthy nodes. For some installations, this delay is too long, and the recovery time needs to be reduced.

### Alerts
Not applicable.

### Stack trace(s)
Not applicable.

### How to resolve
The root cause of this issue is the series of timeouts and delays that occur when Kubernetes detects an offline node. Kubernetes first takes time to discover that a node is unavailable (up to 10 seconds). It then waits for the node to either recover or time out (40 seconds), and finally, it marks the pods on that node for deletion and waits another 5 minutes before redeploying them to healthy nodes.

To reduce this recovery time, you can adjust the following variables:
- `nodeStatusUpdateFrequency`: Kubelet's variable that determines how frequently kubelet computes the node status and sends it to the control-plane. The default is 10s, but it should be twice the value of `node-monitor-period`.
- `node-monitor-period`: Kube-controller-manager's variable that defines the period for syncing NodeStatus. The default is 5s and should be half the value of `nodeStatusUpdateFrequency`.
- `node-monitor-grace-period`: Kube-controller-manager's variable that sets the time a node can be unresponsive before being marked as unhealthy. The default is 40s and should be (N-1) times more than kubelet's `nodeStatusUpdateFrequency`, where N is hardcoded to 5 retries.
- `pod-eviction-timeout`: Kube-controller-manager's variable specifying the grace period before pods on failed nodes are deleted. The default is 5 minutes.

These values can be modified in the `cluster.yaml` during deployment or upgrades. Example configuration:
```yaml
services:
  kubeadm_kubelet:
    nodeStatusUpdateFrequency: 4s
  kubeadm:
    controllerManager:
      extraArgs:
        node-monitor-period: "2s"
        node-monitor-grace-period: "16s"
        pod-eviction-timeout: "30s"
```

Choose the appropriate values according to your environment's stability. If the network or hosts are unstable, adjust these values to avoid unnecessary pod redeployments, as frequent redeployments can increase load and cause instability.

In existing clusters, these variables can be manually updated by modifying `/var/lib/kubelet/config.yaml` for kubelet on all nodes, and `/etc/kubernetes/manifests/kube-controller-manager.yaml` for the controller-manager on the control-plane nodes.

### Recommendations
To avoid long recovery times in the future:
- Regularly monitor the health of your nodes and network, and tune the relevant variables to reduce recovery time in case of node failure.
- Choose timeout values that reflect the stability of your environment to prevent unnecessary pod redeployments, which can lead to additional load and instability.

>**Note**  
>Adjusting these variables can significantly reduce the time it takes for Kubernetes to recover from a node failure.

## `kube-controller-manager` Unable to Sync Caches for Garbage Collector

### Description
The `kube-controller-manager` logs show errors indicating that it is unable to sync caches for the garbage collector. These errors prevent the garbage collector from functioning properly, leading to delays in cleaning up resources.

### Alerts
Not applicable.

### Stack trace(s)
```text
E0402 10:52:00.858591 8 shared_informer.go:226] unable to sync caches for garbage collector
E0402 10:52:00.858600 8 garbagecollector.go:233] timed out waiting for dependency graph builder sync during GC sync (attempt 16)
I0402 10:52:00.883519 8 graph_builder.go:272] garbage controller monitor not yet synced 
```

### How to resolve
The root cause of this issue may be related to etcd I/O performance and a lack of CPU resources for both `kube-apiserver` and etcd. High CPU resource usage by the Kubernetes API affects the control-plane API, the etcd cluster, and the garbage collector's ability to sync.

To resolve this issue, you have two options:
1. **Increase resources** for control-plane nodes to match the current load on the Kubernetes API (`kube-apiserver`).
2. **Reduce the load** on the Kubernetes API if resource scaling is not feasible.

### Recommendations
To avoid this issue in the future:
- Monitor CPU and I/O performance of the control-plane nodes, especially the `kube-apiserver` and etcd.
- Consider resource scaling for the control-plane nodes when the cluster load increases.

>**Note**  
>Proper resource allocation for the control-plane is critical for ensuring that the garbage collector and other control-plane components function smoothly.

## Etcdctl Compaction and Defragmentation

### Description
Errors related to etcd disk space can occur, such as the `database space exceeded` & `no space` messages in the `etcd` pod logs.
Additionally, if the etcd database reaches 70% of the default storage size (2GB by default), defragmentation may be required.

### Alerts
Not applicable.

### Stack trace(s)
```text
etcdserver: mvcc: database space exceeded
etcdserver: no space
```

### How to resolve
The root cause of this issue is fragmented space left after the compaction procedure. While this space is available for etcd, it is not available to the host filesystem. You must defragment the etcd database to make this space available to the filesystem.

Compaction is performed automatically every 5 minutes, and this interval can be adjusted using the `--etcd-compaction-interval` flag for the `kube-apiserver`.

To fix this problem, defragment the etcd database for each cluster member sequentially to avoid cluster-wide latency spikes. Use the following command to defragment an etcd member:
```bash
etcdctl defrag --endpoints=ENDPOINT_IP:2379
```

To defragment all cluster members sequentially, use:
```bash
etcdctl defrag --endpoints=ENDPOINT_IP1:2379, --endpoints=ENDPOINT_IP2:2379, --endpoints=ENDPOINT_IP3:2379
```
Where `ENDPOINT_IP` is the internal IP address of the etcd endpoint.

### Recommendations
Monitor the etcd database regularly to ensure it does not reach the 70% storage limit. Run defragmentation when needed and avoid simultaneous defragmentation of all cluster members.

> **Note**: Defragmentation of a live member blocks the system from reading and writing data while rebuilding its states. Avoid running defragmentation on all etcd members simultaneously.

## Etcdctl Defrag Return Context Deadline Exceeded

### Description
When running the defrag procedure for the etcd database, the following error may occur:
```text
"error":"rpc error: code = DeadlineExceeded desc = context deadline exceeded"}
Failed to defragment etcd member
```

### Alerts
Not applicable.

### Stack trace(s)
Not applicable.

### How to resolve
The root cause of this issue is the default timeout for short-running commands, which is 5 seconds. This timeout may not be enough for defragmentation.

To resolve this issue, use the `--command-timeout` flag to increase the timeout when running the defrag command:
```bash
etcdctl defrag --endpoints=ENDPOINT_IP:2379 --command-timeout=30s
```

### Recommendations
Ensure the command timeout is set appropriately to prevent timeouts during defragmentation of large etcd databases.

> **Note**: Not applicable.

## Etcdserver Request Timeout

### Description
You may encounter error messages like the following in the `kubelet` logs:
```bash
Apr 23 06:32:33 node-9 kubelet: 2023-04-23 06:32:33.378 [ERROR][9428] ipam_plugin.go 309: Failed to release address ContainerID="8938210a16212763148e8fcc3b4785440eea07e52ff82d1f0370495ed3315ffc" HandleID="k8s-pod-network.8938210a16212763148e8fcc3b4785440eea07e52ff82d1f0370495ed3315ffc" Workload="example-workload-name" error=etcdserver: request timed out
```

Additionally, in the etcd logs, you may see:
```bash
2023-04-29 06:06:16.087641 W | etcdserver: failed to send out heartbeat on time (exceeded the 100ms timeout for 6.102899ms, to fa4ddfec63d549fc)
```

### Alerts
Not applicable.

### Stack trace(s)
Not applicable.

### How to resolve
The root cause is that the etcd database processes requests too slowly. To improve etcd performance, first check that the disk under `/var/lib/etcd` meets the performance recommendations outlined in [the etcd documentation](https://etcd.io/docs/v3.5/tuning/).

Then, adjust the following settings in the `/etc/kubernetes/manifests/etcd.yaml` manifest on all control-plane nodes:
```bash
--heartbeat-interval=1000
--election-timeout=5000
```

It is also recommended to set different `snapshot-count` values on different control-plane nodes so that snapshots are persisted to disk at different times. The default value is `10000`. Set different values for each control-plane node:
```bash
# second master: 
--snapshot-count=11210
# third master:
--snapshot-count=12210
```

### Recommendations
Follow the etcd tuning recommendations in the [official etcd documentation](https://etcd.io/docs/v3.5/tuning/) to ensure optimal performance and avoid request timeouts.

> **Note**: Not applicable.

## Etcd Database Corruption

### Description
The etcd cluster is unhealthy, and some etcd pods fail to start with errors such as:
```text
{"level":"panic","ts":"2023-07-30T19:23:07.931Z","caller":"membership/cluster.go:506","msg":"failed to update; member unknown","cluster-id":"61ceb51871c06748","local-member-id":"8a3ba0c8a6fd8c57","unknown-remote-peer-id":"7ed870910216f160","stacktrace":"go.etcd.io/etcd/server/v3/etcdserver/api/membership.(*RaftCluster).UpdateAttributes\n\tgo.etcd.io/etcd/server/v3/etcdserver/api/membership/cluster.go:506\ngo.etcd.io/etcd/server/v3/etcdserver.(*applierV2store).Put\n\tgo.etcd.io/etcd/server/v3/etcdserver/apply_v2.go:92\ngo.etcd.io/etcd/server/v3/etcdserver.(*EtcdServer).applyV2Request\n\tgo.etcd.io/etcd/server/v3/etcdserver/apply_v2.go:135\ngo.etcd.io/etcd/server/v3/etcdserver.(*EtcdServer).applyEntryNormal\n\tgo.etcd.io/etcd/server/v3/etcdserver/server.go:2220\ngo.etcd.io/etcd/server/v3/etcdserver.(*EtcdServer).apply\n\tgo.etcd.io/etcd/server/v3/etcdserver/server.go:2143\ngo.etcd.io/etcd/server/v3/etcdserver.(*EtcdServer).applyEntries\n\tgo.etcd.io/etcd/server/v3/etcdserver/server.go:1384\ngo.etcd.io/etcd/server/v3/etcdserver.(*EtcdServer).applyAll\n\tgo.etcd.io/etcd/server/v3/etcdserver/server.go:1199\ngo.etcd.io/etcd/server/v3/etcdserver.(*EtcdServer).run.func8\n\tgo.etcd.io/etcd/server/v3/etcdserver/server.go:1122\ngo.etcd.io/etcd/pkg/v3/schedule.(*fifo).run\n\tgo.etcd.io/etcd/pkg/v3@v3.5.6/schedule/schedule.go:157"}
panic: failed to update; member unknown
```
Other etcd pods fail to start due to the lack of connection to the failed cluster members.

### Alerts
Not applicable.

### Stack trace(s)
Not applicable.

### How to resolve
The root cause of the issue is a corrupted etcd database. 

If you have a relevant backup created by the [`kubemarine backup`](/documentation/Maintenance.md#backup-procedure) procedure and it is suitable to restore the whole Kubernetes cluster, you can use the [`kubemarine restore`](/documentation/Maintenance.md#restore-procedure) procedure.

If you prefer to restore only the etcd database rather than the entire cluster, you can use the `kubemarine restore` procedure with a list of required tasks:
```bash
kubemarine restore --config=${CLUSTER_YAML} --tasks="prepare,import.etcd,reboot ${PROCEDURE_YAML}"
```

## Manual Restoration of Etcd Database

If it is not possible to use the standard Kubemarine procedure to restore etcd, you can manually restore the etcd database.

### Description
If it is not possible to use the standard Kubemarine procedure to restore etcd, it can be done manually. This involves either restoring etcd from a snapshot or recovering it without one.

### Alerts
Not applicable.

### Stack trace(s)
Not applicable.

### How to resolve
#### Manual Etcd Restoration from a Snapshot

The community recommends to use snapshots to restore etcd database.

A snapshot can be created at a control-plane node this way:

```
# etcdctl snapshot save /var/lib/etcd/snapshot.db

```

**Note**: etcdctl is a script which starts a container with etcd image, so path to the snapshot file should be `/var/lib/etcd`.

To restore etcd database from a snapshot created as it is described above, the following steps should be applied:

1. Stop kubelet at all the control-plane nodes and stop the relevant containerd/docker containers:

```
# systemctl stop kubelet

# for i in "etcd" "kube-apiserver" "kube-controller-manager" "kube-scheduler" ; do crictl stop $(crictl ps -a --name $i -q) ; done

# crictl ps -a | egrep "etcd|kube-apiserver|kube-controller-manager|kube-scheduler"
30f92a80cfaa4       25f8c7f3da61c       47 minutes ago      Exited              etcd                        5                   bfa80629fe7c5
9a20571c8e93c       595f327f224a4       47 minutes ago      Exited              kube-scheduler              7                   6465a21e0022d
795a007ef78da       df7b72818ad2e       47 minutes ago      Exited              kube-controller-manager     8                   101d96258a856
5840381f58a39       8fa62c12256df       47 minutes ago      Exited              kube-apiserver              4                   84a17f819840e

```

2. At a control-plane node backup the content of /var/lib/etcd and clean it up:

```
# cp -a /var/lib/etcd /var/lib/etcd.bkp
# rm -rf /var/lib/etcd/*
```

3. Copy the snapshot from which you are going to restore to `var/lib/etcd`:

```
# cp /tmp/snapshot.db /var/lib/etcd/
``` 

4. Restore etcd database into non-default catalog, for example, into `/var/lib/etcd/tmpdir`:

```
etcdutl snapshot restore /var/lib/etcd/snapshot.db \
            --name=${CONTROL_PLANE_NODE_NAME} \
            --data-dir=/var/lib/etcd/tmpdir \
            --initial-cluster=${INITIAL_CLUSTER} \
            --initial-advertise-peer-urls=https://${CONTROL_PLANE_NODE_INTERNAL_IP}:2380 
```

where
 - `${CONTROL_PLANE_NODE_NAME}` - the name of a node where the database is being restored
 - `${INITIAL_CLUSTER}` - the list of etcd cluster members, for example:
```
cp-node-1=http://192.168.0.10:2380,cp-node-2=http://192.168.0.11:2380,cp-node-3=http://192.168.0.12:2380
```
 - `${CONTROL_PLANE_NODE_INTERNAL_IP}` - the internal IP address of the `${CONTROL_PLAN_NODE_NAME}` node

5. Move etcd database to its default folder and delete all unnecessary data:

```
# mv /var/lib/etcd/tmpdir/member /var/lib/etcd/member && \
  rm -rf /var/lib/etcd/tmpdir /var/lib/etcd/snapshot.db
```

6. Repeat steps 2-5 at all the control-plane nodes with etcd.

7. Disable autostart of all the control-plane pods except etcd and start kubelet at all the control-plane nodes:

```
# mkdir /etc/kubernetes/manifests-down
# mv /etc/kubernetes/manifests/{kube-apiserver.yaml,kube-controller-manager.yaml,kube-scheduler.yaml} /etc/kubernetes/manifests-down/
# systemctl start kubelet
```

8. Check that etcd has started at all the control-plane nodes and the etcd cluster looks healthy:

```
# etcdctl member list
# etcdctl endpoint status --cluster -w table
``` 

9. If etcd cluster is healthy, start all other control-plane pods at all the control-plane nodes and check if the k8s cluster is alive:

```
# mv /etc/kubernetes/manifests-down/{kube-apiserver.yaml,kube-controller-manager.yaml,kube-scheduler.yaml} /etc/kubernetes/manifests/
# rmdir /etc/kubernetes/manifests-down
# kubectl get nodes
```

10. If necessary, remove the backup files created at the step 2.


#### Manual Etcd Restoration without a Snapshot

In case you have an unhealthy or fully misconfigured etcd cluster and a backup snapshot is unavailable, you can re-create it from one of the etcd cluster members.

1. Define which of etcd nodes has the latest version of the database. You can check timestamp on database files by `ls -la`.

2. Stop the control-plane pods and their containers at all the control-plane nodes:

```
# mkdir /etc/kubernetes/manifests-down

# mv /etc/kubernetes/manifests/{etcd.yaml,kube-apiserver.yaml,kube-controller-manager.yaml,kube-scheduler.yaml} /etc/kubernetes/manifests-down/

# for i in "etcd" "kube-apiserver" "kube-controller-manager" "kube-scheduler" ; do crictl stop $(crictl ps -a --name $i -q) ; done

# crictl ps -a | egrep "etcd|kube-apiserver|kube-controller-manager|kube-scheduler"
30f92a80cfaa4       25f8c7f3da61c       47 minutes ago      Exited              etcd                        5                   bfa80629fe7c5
9a20571c8e93c       595f327f224a4       47 minutes ago      Exited              kube-scheduler              7                   6465a21e0022d
795a007ef78da       df7b72818ad2e       47 minutes ago      Exited              kube-controller-manager     8                   101d96258a856
5840381f58a39       8fa62c12256df       47 minutes ago      Exited              kube-apiserver              4                   84a17f819840e
```

3. Make backup of etcd data at all the control-plane nodes: 

```
cp -a /var/lib/etcd /var/lib/etcd.bkp
```

4. On the etcd cluster member with the latest database files add the `--force-new-cluster` flag to the etcd manifest:

```
# vi /etc/kubernetes/manifests-down/etcd.yaml
...
spec:
  containers:
  - command:
    - etcd
    ...
    - --force-new-cluster
...

```

and start etcd:

```
# mv /etc/kubernetes/manifests-down/etcd.yaml /etc/kubernetes/manifests/etcd.yaml
# crictl ps | grep etcd
```

5. Check etcd cluster status:

```
# etcdctl member list
# etcdctl endpoint status --cluster -w table
``` 

6. If everything looks fine, remove `--force-new-cluster` flag from /etc/kubernetes/manifests/etcd.yaml. Etcd pod will be restarted automatically.

7. Add a new cluster member:

```
etcdctl --endpoints=${CP_NODE_1_INTERNAL_IP}:2379 member add ${CP_NODE_2} --peer-urls=https://${CP_NODE_2_INTERNAL_IP}:2380
```

where
 - `${CP_NODE_1_INTERNAL_IP}` - internal IP address of the first etcd cluster member
 - `${CP_NODE_2}` - name of the new etcd cluster member
 - `${CP_NODE_2_INTERNAL_IP}` - internal IP address of the new etcd cluster member

8. At the new cluster member clean up `/var/lib/etcd` folder:

```
# rm -rf /var/lib/etcd/*
```

9. At the new cluster member change `--initial-cluster` and `--initial=cluster-state` flags:

``` 
# vi /etc/kubernetes/manifests-down/etcd.yaml
...
spec:
  containers:
  - command:
    - etcd
    ...
    - --initial-cluster=${CP_NODE_1}=https://${CP_NODE_1_INTERNAL_IP}:2380,${CP_NODE_2}=https://${CP_NODE_2_INTERNAL_IP}:2380
    - --initial-cluster-state=existing
...
```

where
 - `${CP_NODE_1}` - the name of the first etcd cluster member
 - `${CP_NODE_1_INTERNAL_IP}` - the internal IP address of the first etcd cluster member
 - `${CP_NODE_2}` - the name of the added etcd cluster member
 - `${CP_NODE_2_INTERNAL_IP}` - the internal IP address of the added etcd cluster member
 - `--initial-cluster` should contain all already existing etcd cluster members and a newly added etcd cluster member

and restart etcd:

```
# mv /etc/kubernetes/manifests-down/etcd.yaml /etc/kubernetes/manifests/etcd.yaml
```

10. Check etcd cluster status:

```
# etcdctl member list
# etcdctl endpoint status --cluster -w table
```

11. Repeat steps 7-10 for other nodes which should be added to the etcd cluster.

12. If etcd cluster is healthy, start all other control-plane pods at all the control-plane nodes and check if the k8s cluster is alive:

```
# mv /etc/kubernetes/manifests-down/{kube-apiserver.yaml,kube-controller-manager.yaml,kube-scheduler.yaml} /etc/kubernetes/manifests/
# rmdir /etc/kubernetes/manifests-down
# kubectl get nodes
```

13. If necessary, remove backup files create at the step 3.

### Recommendations
If only etcd is corrupted and the rest of the cluster is healthy, it is advised to restore just the etcd database. 

> **Note**: The `reboot` task will reboot all the cluster nodes.


## HTTPS Ingress Doesn't Work

### Description
The secure connection is not being established, and the server does not support the required ciphers. This issue occurs when the `ingress-nginx-controller` does not support certain ciphers from TLSv1.2 and TLSv1.3 by default.

### Alerts
Not applicable.

### Stack trace(s)
Not applicable.

### How to resolve
The root cause of the issue is that `ingress-nginx-controller` does not support all ciphers from TLSv1.2 and TLSv1.3 by default. The default list of ciphers is embedded in the `ingress-nginx-controller` image in the `/etc/nginx/nginx.conf` file. These settings can be customized during the installation process by modifying the `config_map` section, as described in the [nginx-ingress-controller plugin documentation](https://github.com/Netcracker/KubeMarine/blob/main/documentation/Installation.md#nginx-ingress-controller).

To resolve this issue, update the `Ingress` resource by adding an annotation that manages the list of supported ciphers. The following example adds the `AES128-SHA256` cipher, which is not supported by default:

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  annotations:
    nginx.ingress.kubernetes.io/ssl-ciphers: "AES128-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384"
...
```

### Recommendations
To avoid this issue in the future:
- Customize the cipher list during the installation of `ingress-nginx-controller` if your environment requires specific ciphers.
- Review and update the `Ingress` resource annotations to include necessary ciphers based on your security requirements.

>**Note**  
>For more information on configuring ciphers, see the `config_map` section in the nginx-ingress-controller documentation.

## Garbage Collector Does Not Initialize If Convert Webhook Is Broken

### Description
If the pod deletion process is running in the background (the default setting), the namespace quota is not updated. When pod deletion is in the foreground, pods may freeze in the `Terminating` state. Additionally, if a new quota is created, the REQUEST and LIMIT fields remain empty:
```bash
# kubectl get quota -n test
NAME            AGE    REQUEST   LIMIT
default-quota   79m
```

### Alerts
Not applicable.

### Stack trace(s)
Not applicable.

### How to resolve
The root cause of this issue is a broken converter webhook associated with a Custom Resource Definition (CRD). This prevents the garbage collector (GC) controller from initializing due to a failure during the informer sync process. The issue remains hidden until the GC controller restarts, as CRDs with non-working converter webhooks do not affect ongoing GC operations but break GC initialization.

This is a known issue in the Kubernetes community (see [GitHub issue](https://github.com/kubernetes/kubernetes/issues/101078)), but no fix has been implemented yet.

To resolve the issue:
1. Check the `kube-controller-manager` pod logs for messages similar to the following:
   ```bash
   E1202 03:28:26.861927       1 reflector.go:138] k8s.io/client-go/metadata/metadatainformer/informer.go:90: Failed to watch *v1.PartialObjectMetadata: failed to list *v1.PartialObjectMetadata: conversion webhook for deployment.example.com/v1alpha22, Kind=example_kind failed: Post "https://example.svc:443/convertv1-96-0-rc3?timeout=30s": service "example-deployments-webhook-service" not found
   ```

2. From this log, identify the CR kind (in this example, `example_kind`). Use it to locate the broken CRD:
   ```bash
   # kubectl get crd -o custom-columns=CRD_Name:.metadata.name,CR_Kind:.spec.names.kind | grep example_kind
   crd_example.com                               example_kind
   ```

3. Restore the broken webhook if possible. If restoring the webhook is not feasible, delete the problematic CRD. This action should restore the garbage collector's functionality.

### Recommendations
To avoid this issue in the future:
- Ensure that custom converter webhooks are thoroughly tested before being used in production.
- Regularly monitor the `kube-controller-manager` logs for early signs of webhook-related issues.

>**Note**  
>This issue is currently unresolved in the Kubernetes community, so carefully manage CRDs and associated webhooks to prevent similar disruptions.


## Pods Stuck in "Terminating" Status During Deletion

### Description
This issue occurs when pods get stuck in the "Terminating" status and are not deleted properly. It is specifically applicable to hosts running RHEL or CentOS 7.x versions (starting from 7.4) where the `containerd` container runtime is used.

### Alerts
Not applicable.

### Stack trace(s)
Not applicable.

### How to resolve
To resolve the issue, add the following parameter to the `/etc/sysctl.conf` file:
```bash
fs.may_detach_mounts=1
```
After adding the parameter, apply the changes by running:
```bash
sysctl -p
```

### Recommendations
Ensure that this setting is only applied on RHEL or CentOS 7.x systems (starting from 7.4) where the `containerd` container runtime is being used.

>**Note**  
>This solution is specifically intended for RHEL and CentOS 7.x environments.

## Random 504 Error on Ingresses

### Description
Sometimes ingresses return a 504 error (Gateway Timeout) even when the backend pods are up and running. Additionally, traffic between pods located on different nodes is not routed properly.

### Alerts
Not applicable.

### Stack trace(s)
Not applicable.

### How to resolve
The root cause of this issue is a network policy applied at the infrastructure level that blocks traffic for the `podSubnet` and/or `serviceSubnet` on the nodes' ports.

To resolve the issue, ensure that the [prerequisites](/documentation/Installation.md#prerequisites-for-cluster-nodes) for `podSubnet` and `serviceSubnet` are properly configured.

For OpenStack IaaS environments:
1. Check both the Security Group settings and the Allowed Address Pairs settings (if Port Security is enabled on the nodes' ports).
2. Verify the Port Security status for the port:
   ```bash
   openstack port show -c port_security_enabled ${PORT_ID}
   ```
3. Add the `podSubnet` and `serviceSubnet` networks to the Allowed Address Pairs for the port:
   ```bash
   openstack port set --allowed-address ip-address=10.128.0.0/14 ${PORT_ID} --insecure
   openstack port set --allowed-address ip-address=172.30.0.0/16 ${PORT_ID} --insecure
   ```

### Recommendations
Verify the network policies and configurations, especially in environments with Port Security enabled, to ensure that the `podSubnet` and `serviceSubnet` networks have the necessary access.

>**Note**  
>This solution is applicable to environments where infrastructure-level network policies may affect traffic between nodes.


## Nodes Have `NotReady` Status Periodically

### Description
Nodes running on Ubuntu 20.04 may periodically enter the `NotReady` status without significant workload. The `kubelet` logs contain the following message:

```bash
Nov 28 14:02:06 node01 kubelet[308309]: E1128 14:02:06.631719  308309 kubelet.go:1870] "Skipping pod synchronization" err="PLEG is not healthy: pleg was last seen active 3m0.416753742s ago; threshold is 3m0s"
```

### Alerts
Not applicable.

### Stack trace(s)
Not applicable.

### How to resolve
The root cause of this issue is a known problem with the Linux kernel version `5.4.0-132-generic`, which affects the Container Runtime Interface (CRI).

To resolve the issue, upgrade the Linux kernel to `5.4.0-135-generic`.

### Recommendations
Regularly update the Linux kernel to avoid known issues that may affect the stability of nodes, particularly those related to the CRI.

>**Note**  
>This solution specifically applies to Ubuntu 20.04 with kernel version `5.4.0-132-generic`.


## Long Pulling of Images

### Description
Pods may get stuck in the `ContainerCreating` status for an extended period of time. The event logs show that pulling an image takes several minutes or longer:
```bash
Successfully pulled image "<image_name>" in 12m37.752058078s
```

### Alerts
Not applicable.

### Stack trace(s)
Not applicable.

### How to resolve
The root cause is that, by default, kubelet pulls images sequentially, one by one. A slow image pull can delay all other image pulls on the node.

To resolve the issue, add the following parameter to the kubelet configuration to allow parallel image pulls:
```bash
--serialize-image-pulls=false
```

> **Note**: It is recommended not to change the default value (`--serialize-image-pulls=true`) on nodes running a Docker daemon with version < 1.9 or using the `aufs` storage backend.

### Recommendations
In environments with newer Docker versions and non-aufs storage backends, enabling parallel image pulls can significantly reduce the time it takes to pull images and improve pod startup times.

>**Note**  
>Ensure compatibility with your Docker version and storage backend before making this change.


## No Pod-to-Pod Traffic for Some Nodes with More Than One Network Interface

### Description
There is no traffic between pods located on different nodes, and the affected nodes have more than one permanent network interface.

### Alerts
Not applicable.

### Stack trace(s)
Not applicable.

### How to resolve
The root cause is that not all Calico BGP sessions between nodes are established due to incorrect network interface selection. By default, Calico uses the `first-found` method, which selects the first valid IP address on the first network interface to route traffic between nodes. This approach works for nodes with a single Ethernet interface but may cause issues in cases where multiple interfaces are present.

To resolve this, specify the correct network interface for Calico in the `IP_AUTODETECTION_METHOD` variable. For example:
```yaml
plugins:
  calico:
    env:
      IP_AUTODETECTION_METHOD: interface=ens160
```

For more details on IP autodetection methods, refer to the [official Calico documentation](https://docs.tigera.io/calico/3.25/reference/configure-calico-node#ip-autodetection-methods).

### Recommendations
Ensure that the appropriate network interface is set for nodes with multiple network interfaces to avoid routing issues in Calico.

>**Note**  
>Consult the Calico documentation for best practices when configuring IP autodetection methods.


## No Pod-to-Pod Traffic for Some Nodes with More Than One IPs with Different CIDR Notation

### Description
There is no traffic between pods located on different nodes, and the nodes in question have more than one IP on the network interface, with different CIDR notations.

### Alerts
Not applicable.

### Stack trace(s)
Not applicable.

### How to resolve
The root cause is that not all Calico BGP sessions between nodes are established due to different CIDR notations on the chosen IPs for nodes. This issue often occurs in setups where the balancer role is combined with other roles, such as with VRRP, where Calico may autodetect the VRRP IP instead of the node's internal IP.

You can use `calicoctl` to inspect this situation. For example, in a Mini-HA cluster, the output may look like this:
```bash
sudo calicoctl get nodes --output=wide
NAME                  ASN       IPV4                IPV6
k8s-control-plane-1   (64512)   192.168.0.250/32
k8s-control-plane-2   (64512)   192.168.0.2/24
k8s-control-plane-3   (64512)   192.168.0.3/24
```

By default, Calico uses the `first-found` method to select the first valid IP address on the first network interface to route traffic between nodes. This method works well for nodes with a single IP but may cause issues when multiple IPs with different CIDR notations are present.

To avoid this, change Calico's `IP_AUTODETECTION_METHOD` variable to `kubernetes-internal-ip` or another method that suits your environment:
```yaml
plugins:
  calico:
    install: true
    env:
      IP_AUTODETECTION_METHOD: kubernetes-internal-ip
```

> **Note**: The `kubernetes-internal-ip` autodetection method cannot be used in Calico versions earlier than v3.24.0 due to a [known issue](https://github.com/projectcalico/calico/issues/6142). The fix has also been backported to Calico v3.22.4 and v3.23.2.

### Recommendations
Ensure that Calico is configured to detect the correct IPs when nodes have multiple IP addresses with different CIDR notations, particularly in complex networking setups involving VRRP or similar configurations.

>**Note**  
>For more information on IP autodetection methods, refer to the [official documentation](https://docs.tigera.io/calico/3.25/reference/configure-calico-node#ip-autodetection-methods).


## Ingress Cannot Be Created or Updated

### Description
An ingress cannot be created or updated, and the following error is displayed:
```bash
Internal error occurred: failed calling webhook "validate.nginx.ingress.kubernetes.io": failed to call webhook: Post "https://ingress-nginx-controller-admission.ingress-nginx.svc:443/networking/v1/ingresses?timeout=10s": context deadline exceeded
```

### Alerts
Not applicable.

### Stack trace(s)
Not applicable.

### How to resolve
The root cause of this issue is that in clusters with a large number of ingresses, the admission webhook may take too long to test a new configuration, exceeding the timeout.

There are two ways to resolve this issue:

1. **Increase the webhook timeout**:
   ```bash
   kubectl edit ValidatingWebhookConfiguration ingress-nginx-admission
   ...
     timeoutSeconds: 30
   ```

2. **Disable the full test** by adding the `--disable-full-test` argument for the ingress-nginx-controller:
   ```bash
   kubectl edit ds ingress-nginx-controller
   ...
   spec:
     containers:
         args:
           - '--disable-full-test'
   ```

### Recommendations
For clusters with a large number of ingresses, consider increasing the timeout or disabling the full test to ensure the ingress-nginx-controller can handle updates in a timely manner.

>**Note**  
>Adjust the timeout value according to your cluster's performance and workload requirements.


## vIP Address is Unreachable

### Description
The installation process failed with the following error, indicating that the Kubernetes API's vIP address is unreachable:
```bash
.....
<DATETIME> VERBOSE [log.verbose] I1220 14:12:57.517911    3239 waitcontrolplane.go:83] [wait-control-plane] Waiting for the API server to be healthy
<DATETIME> VERBOSE [log.verbose] I1220 14:12:58.520621    3239 with_retry.go:234] Got a Retry-After 1s response for attempt 1 to https://api.example.com:6443/healthz?timeout=10s
<DATETIME> VERBOSE [log.verbose] I1220 14:12:59.522460    3239 with_retry.go:234] Got a Retry-After 1s response for attempt 2 to https://api.example.com:6443/healthz?timeout=10s
<DATETIME> VERBOSE [log.verbose] I1220 14:13:00.523457    3239 with_retry.go:234] Got a Retry-After 1s response for attempt 3 to https://api.example.com:6443/healthz?timeout=10s
<DATETIME> VERBOSE [log.verbose] I1220 14:13:01.524729    3239 with_retry.go:234] Got a Retry-After 1s response for attempt 4 to https://api.example.com:6443/healthz?timeout=10s
<DATETIME> VERBOSE [log.verbose] I1220 14:13:02.526164    3239 with_retry.go:234] Got a Retry-After 1s response for attempt 5 to https://api.example.com:6443/healthz?timeout=10s
<DATETIME> VERBOSE [log.verbose] I1220 14:13:03.529524    3239 with_retry.go:234] Got a Retry-After 1s response for attempt 6 to https://api.example.com:6443/healthz?timeout=10s
<DATETIME> VERBOSE [log.verbose] I1220 14:13:04.530520    3239 with_retry.go:234] Got a Retry-After 1s response for attempt 7 to https://api.example.com:6443/healthz?timeout=10s
<DATETIME> VERBOSE [log.verbose] I1220 14:13:05.531711    3239 with_retry.go:234] Got a Retry-After 1s response for attempt 8 to https://api.example.com:6443/healthz?timeout=10s
<DATETIME> VERBOSE [log.verbose] I1220 14:13:06.532613    3239 with_retry.go:234] Got a Retry-After 1s response for attempt 9 to https://api.example.com:6443/healthz?timeout=10s
202
.....
<DATETIME> VERBOSE [log.verbose] couldn't initialize a Kubernetes cluster
.....
<DATETIME> CRITICAL [errors.error_logger] TASK FAILED deploy.kubernetes.init
<DATETIME> CRITICAL [errors.error_logger] KME0002: Remote group exception
```

The logs suggest that the vIP address for the Kubernetes API is unreachable.

### Alerts
Not applicable.

### Stack trace(s)
Not applicable.

### How to resolve
1. **Check if the vIP address is unreachable**:
   Verify connectivity to the Kubernetes API via the vIP address:
   ```bash
   ping -c 1 -W 2 api.example.com
   ```

   Example output if the IP address is unreachable:
   ```bash
   PING api.example.com (10.10.10.144) 56(84) bytes of data.

   --- api.example.com ping statistics ---
   1 packets transmitted, 0 received, 100% packet loss, time 0ms
   ```

   In this case, the IP address `10.10.10.144` (the floating IP for the internal `192.168.0.4`) is unreachable.

2. **Check if the vIP is managed by keepalived and assigned to the correct network interface**:
   Verify that the vIP is associated with the correct interface on the node that serves as the balancer:
   ```bash
   sudo ip a
   ```

   Example output:
   ```bash
   2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
       link/ether fa:16:3e:54:45:74 brd ff:ff:ff:ff:ff:ff
       altname enp0s3
       altname ens3
       inet 192.168.0.11/24 brd 192.168.0.255 scope global dynamic noprefixroute eth0
         valid_lft 36663sec preferred_lft 36663sec
       inet 192.168.0.4/32 scope global vip_2910a02af7
         valid_lft forever preferred_lft forever
   ```

3. **Ping the internal IP address from any worker node**:
   ```bash
   ping -c 1 -W 2 192.168.0.4
   ```

   Example output if the internal IP is unreachable:
   ```bash
   PING 192.168.0.4 (192.168.0.4) 56(84) bytes of data.

   --- 192.168.0.4 ping statistics ---
   1 packets transmitted, 0 received, 100% packet loss, time 0ms
   ```

4. **Check the ARP table for the correct MAC address**:
   Ensure that the MAC address listed in the ARP table matches the correct address of the interface on the node with the balancer. For example:
   ```bash
   sudo arp -a | grep 192.168.0.4
   ```

   Example output on the worker node:
   ```bash
   <NODENAME> (192.168.0.4) at 10:e7:c6:c0:47:35 [ether] on ens3
   ```

   If the MAC address does not match (e.g., it shows `10:e7:c6:c0:47:35` instead of the correct `fa:16:3e:54:45:74`), this indicates that the GARP (Gratuitous ARP) protocol is disabled, preventing `keepalived` from announcing the correct MAC address for the vIP.

5. **Solution**:
   If GARP is disabled in your environment and `keepalived` cannot announce the new MAC address for the vIP, contact technical support and request that the GARP protocol be enabled.
   
### Recommendations
Ensure that GARP is enabled in your environment to allow `keepalived` to function correctly for managing vIP addresses.

>**Note**  
>Not applicable.

## CoreDNS Cannot Resolve the Name

### Case 1
### Description
Pod Cannot Resolve a Short Name: A pod is unable to resolve a short name. When checking the pod's DNS resolution, the following error appears:

```bash
$ nslookup kubernetes.default
Server:         172.30.0.10
Address:        172.30.0.10:53

** server can't find kubernetes.default: NXDOMAIN
```

### Alerts
Not applicable.

### Stack trace(s)
Not applicable.

### How to resolve
The root cause of this issue is that images using the `busybox` utility, which provides the `nslookup` command, can have issues handling the `search` directives in `/etc/resolv.conf`.

To resolve the issue, use the Fully Qualified Domain Name (FQDN) instead of the short name. For example, use `kubernetes.default.svc.cluster.local` instead of `kubernetes.default`.

In some cases, installing the `bind-tools` package within the pod can also resolve issues with short names.

### Recommendations
For more details, you can refer to:
- [Busybox nslookup issues](https://github.com/docker-library/busybox/issues/48)
- [Known DNS issues with Alpine in Kubernetes](https://stackoverflow.com/questions/65181012/does-alpine-have-known-dns-issue-within-kubernetes)

### Case 2

### Description
A pod that is attached to `hostNetwork` cannot resolve a name periodically or constantly, even if it is FQDN. The following error message is displayed:

```bash
$ nslookup kubernetes.default.svc.cluster.local
;; connection timed out; no servers could be reached
```

### Alerts
Not applicable.

### Stack trace(s)
Not applicable.

### How to resolve
The root cause of this issue is that traffic from the node network to the pod network is blocked for UDP port 53, which is required for DNS resolution.

To resolve the issue, update the cloud provider configuration to allow traffic between the node and pod networks, specifically for UDP port 53.

In OpenStack environments, this can be managed by adjusting the Security Groups to allow the necessary traffic.

### Recommendations
Ensure that the cloud provider or IaaS network configuration allows traffic on UDP port 53 between node and pod networks, particularly when using `hostNetwork` pods.

> **Note**: Not applicable.


## Pods do not Start Properly

### Description
Pods do not start properly, and the `Audit` daemon logs the following message:
```bash
Error receiving audit netlink packet (No buffer space available)
```

### Alerts
Not applicable.

### Stack trace(s)
Not applicable.

### How to resolve
The root cause is an internal issue with the `Audit` daemon. To resolve this, either change the configuration of the `Audit` daemon or disable it entirely.

### Recommendations
Consider adjusting the buffer size in the `Audit` daemon configuration to avoid resource limitations or disable the `Audit` daemon if it is not essential for your environment.

> **Note**: Not applicable.

## Calico Generates High Amount of Logs and Consumes a lot of CPU

### Description
Calico-node pods generate a lot of logs and consume a lot of resources that causes pod restart. Such logs can be found in calico-node pods:

```bash
[WARNING][89] felix/int_dataplane.go 1822: failed to wipe the XDP state error=failed to load BPF program (/usr/lib/calico/bpf/filter.o): stat /sys/fs/bpf/calico/xdp/prefilter_v1_calico_tmp_A: no such file or directory
libbpf: Error loading BTF: Invalid argument(22)
```

### Alerts
Not applicable.

### Stack trace(s)
Not applicable.

### How to resolve
As WA XDP acceleration can be turned off by adding the following parameter:

#### Manualy
```bash
 kubectl -n kube-system edit ds calico-node
...
spec:
  template:
    spec:
      containers:
      - env:
...
        - name: FELIX_XDPENABLED
          value: "false"
... 
```
#### Using KubeMarine

Define this parameter in `cluster.yaml` like:

```bash
plugins:
  calico:
    install: true
    env:
      FELIX_XDPENABLED: 'false'
```
And run `kubemarine install --tasks=deploy.plugins`

Pods should stop generating such amount of logs and resource consumption should normalize.


## Calico 3.29.0 Leading to kubernetes Controller Manager GC Failures

### Description

On Calico versions 3.29.0 and 3.29.1, the Kubernetes garbage collector is not deleting objects with ownerReferences because it fails to build the dependency graph.
Such logs can be found in kube-controller-manager pod:

```bash
E0508 08:05:31.194320       1 shared_informer.go:316] unable to sync caches for garbage collector
E0508 08:05:31.194365       1 garbagecollector.go:268] timed out waiting for dependency graph builder sync during GC sync (attempt 9425) 
```

### Alerts
Not applicable.

### Stack trace(s)
Not applicable.

### How to resolve
Root cause of the issue is the garbage collector cannot proceed because it is unable to list or watch `tier.[global]networkpolicies.projectcalico.org`, which prevents it from syncing its internal cache.

The best way to resolve this issue is to upgrade Calico to a newer version. However, the following workaround is also applicable:

Create the necessary `RBAC` permissions to allow kube-controller-manager to read `tier.[global]networkpolicies.projectcalico.org` resources.

```yaml
kind: ClusterRole
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: tier-default-reader
rules:
  - apiGroups: ['projectcalico.org']
    resources: ['tiers']
    resourceNames: ['default']
    verbs: ['get']
  - apiGroups: ['projectcalico.org']
    resources: ['tier.networkpolicies']
    resourceNames: ['default.*']
    verbs: ['get', 'list']
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: kube-controller-manager-tier-reader
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: tier-default-reader
subjects:
- apiGroup: rbac.authorization.k8s.io
  kind: User
  name: system:kube-controller-manager
```

# Troubleshooting Kubemarine

This section provides troubleshooting information for Kubemarine-specific or installation-specific issues.

## Operation not Permitted Error in Kubemarine Docker Run

### Description
Some commands in Kubemarine Docker fail with the "Operation not permitted" error. These commands can vary, such as creating a new thread for Kubemarine or executing a simple `ls` command.

### Alerts
Not applicable.

### Stack trace(s)
Not applicable.

### How to resolve
The root cause of this issue is incompatibility between the Docker version and the Kubemarine base [image version](/Dockerfile#L1). Kubemarine uses system calls that are not allowed by default in Docker, causing the failure.

To fix this issue:
1. **Check for compatibility issues** between the Docker version being used and the Kubemarine base [image version](/Dockerfile#L1). If there are known issues, upgrade Docker to a version that resolves them.
   
2. **Use additional grants** for the Kubemarine container by adding the `--privileged` or `--cap-add` options to the Docker command to provide the necessary permissions.

Example of the problem: Kubemarine image `v0.25.0` runs the `ls -la` command on `CentOS 7.5` with Docker version `1.13.1-102`:
```bash
$ docker run --entrypoint ls kubemarine:v0.25.0 -la
ls: cannot access '.': Operation not permitted
ls: cannot access '..': Operation not permitted
ls: cannot access '.dockerignore': Operation not permitted
total 0
d????????? ? ? ? ?            ? .
d????????? ? ? ? ?            ? ..
-????????? ? ? ? ?            ? .dockerignore
```

The root cause is that the `coreutils 8.32` library, installed in this Kubemarine image, uses `statx` system calls for the `ls` command. However, these calls were added to Docker’s whitelist only in version `1.13.1-109`. As a result, the command works only in this or newer Docker versions.

### Recommendations
To prevent this issue in the future:
- Use the `--privileged` or `--cap-add` flags when necessary to avoid permission issues when running system calls in Docker containers.

**Note**: Not applicable.

## Failures During Kubernetes Upgrade Procedure

### Upgrade Procedure Failure, Upgrade Not Completed

### Description
The `upgrade` procedure fails at some point, leaving the upgrade process in an incomplete state. This failure interrupts the upgrade and requires corrective action before the process can be completed.

### Alerts
Not applicable.

### Stack trace(s)
Not applicable.

### How to resolve
The root cause of this issue is any error that occurs during the `upgrade` procedure, leading to its failure. 

To resolve the issue:
1. **Identify the root cause of the failure** and fix it. You can refer to other troubleshooting sections in this guide to help diagnose the issue.
2. Once the cause is resolved, **restart the `upgrade` procedure**. However, before restarting, it is essential to **check the current status** of the upgrade process. Depending on the progress, you may need to update the procedure parameters in files like `cluster.yaml` and the procedure inventory.

   For example, if you are performing an upgrade from version `1.16.12 -> 1.17.7 -> 1.18.8`, and the upgrade fails at version `1.18.8` but is completed for version `1.17.7`, you must:
   - Update `cluster.yaml` with the latest information from the regenerated inventory (as `cluster.yaml` is regenerated after each minor version upgrade).
   - Remove version `1.17.7` from the procedure inventory.

   It is safe to retry upgrades for version `X.Y.Z`, but only up to the point where the next version `X.Y+1.M` upgrade starts. It is incorrect to retry the upgrade to version `1.17.7` after the upgrade to version `1.18.8` has already begun.

### Recommendations
Ensure that the upgrade is only retried for the current version, and any intermediate versions that were successfully upgraded should be removed from the procedure inventory.

**Note**: Not applicable.


### Cannot Drain Node Because of PodDisruptionBudget

### Description
The `upgrade` procedure fails during the node drain process due to PodDisruptionBudget (PDB) limits. Kubernetes cannot proceed with draining the pods because it would violate the PDB rules set by an application.

### Alerts
Not applicable.

### Stack trace(s)
Not applicable.

### How to resolve
The root cause of the issue is that draining a pod would violate the PDB rules configured by an application.

To resolve this issue:
- Starting from Kubernetes version 1.18, you can configure the upgrade procedure to ignore PDB rules using the `disable-eviction` option. This option is enabled by default in version 1.18 and above.
  
- If you encounter this issue on Kubernetes versions lower than 1.18, temporarily **lower the PDB limits** to allow the pods to be drained. Once the pods are drained and the node is updated, run the `upgrade` procedure again. After the upgrade, you must **restore the PDB limits** to their original values.

### Recommendations
For Kubernetes versions lower than 1.18, ensure that PDB limits are temporarily adjusted during upgrades and restored afterward. For versions 1.18 and above, use the `disable-eviction` option to bypass PDB limitations during the upgrade.

**Note**: Not applicable.

### Cannot Drain Node Because of Pod Stuck in "Terminating" Status

### Description
The `upgrade` procedure fails during the node drain process due to a pod being stuck in the "Terminating" status. This prevents the node from being drained and halts the upgrade process.

### Alerts
Not applicable.

### Stack trace(s)
Not applicable.

### How to resolve
The root cause of this issue is a pod that is stuck in the "Terminating" status. There can be various reasons for this behavior, so it's important to check the pod events for more details. To proceed with the upgrade, the "Terminating" pod needs to be deleted.

To resolve the issue, follow these steps:
1. Attempt to forcefully delete the stuck pod with the following command:
   ```bash
   kubectl delete pod <PODNAME> --grace-period=0 --force --namespace <NAMESPACE>
   ```
2. If the force delete does not resolve the issue, try rebooting the node where the pod is stuck in the "Terminating" status.

After the "Terminating" pod is successfully deleted, run the `upgrade` procedure again.

### Recommendations
Monitor for pods stuck in the "Terminating" status during upgrades, and ensure they are deleted or handled appropriately to avoid interruptions in the upgrade process.

**Note**: Not applicable.


### Etcd Pod Customizations Are Missing After Upgrade

### Description
After an upgrade, you may notice that your etcd customizations are no longer present in the `/etc/kubernetes/manifests/etcd.yaml` file. This can happen if the customizations were not properly preserved during the upgrade process.

### Alerts
Not applicable.

### Stack trace(s)
Not applicable.

### How to resolve
The root cause of this issue is that the etcd configuration is re-generated by kubeadm during the upgrade using data from the `kubeadm-config` config map in the `kube-system` namespace. If your customizations are not present in this config map or in `cluster.yaml`, they will be missing after the upgrade.

To resolve this issue:
1. Ensure that your customizations are included in both the `/etc/kubernetes/manifests/etcd.yaml` file and the `kubeadm-config` config map in the `kube-system` namespace.
   
   For example, if you want to increase the etcd snapshot count from 10000 to 10001, modify the `kubeadm-config` config map as follows:
   ```yaml
   data:
     ClusterConfiguration: |
       etcd:
         local:
           extraArgs:
             snapshot-count: "10001"
   ```

   The key should match the etcd argument, and the value should be quoted. After the upgrade, this will result in the following etcd argument:
   ```yaml
   spec:
     containers:
     - command:
       - etcd
       - --snapshot-count=10001
   ```

2. Remember that these customizations are applied by kubeadm only during the upgrade. Therefore, you must manually add your customizations to both the `/etc/kubernetes/manifests/etcd.yaml` file and the `kubeadm-config` config map.

3. Ensure that all custom settings for etcd, `kube-apiserver`, `kube-controller`, and `kube-scheduler` are also reflected in the `cluster.yaml` file. Refer to [services.kubeadm parameters](Installation.md#kubeadm) for more details.

### Recommendations
To preserve your customizations during future Kubernetes upgrades, ensure they are properly reflected in both the `kubeadm-config` config map and `cluster.yaml`.

**Note**: Not applicable.

### Kubernetes Image Repository Does Not Change During Upgrade

### Description
During an upgrade, you expect Kubernetes to use a new image repository, but Kubernetes keeps using the old image repository. As a result, Kubernetes may fail to find the required images, causing the upgrade to fail.

### Alerts
Not applicable.

### Stack trace(s)
Not applicable.

### How to resolve
The root cause of this issue is that the kubeadm cluster configuration is not automatically updated by `kubemarine` during the upgrade process. Specifically, `kubemarine` does not provide a way to change the Kubernetes image repository automatically during an upgrade.

To resolve this issue, you must manually update the image repository in the kubeadm configuration and the container runtime configuration. You must also modify the `cluster.yaml` file to reflect these changes.

1. **Update the kubeadm configuration**:
   Use the following command to edit the kubeadm configuration:
   ```bash
   kubectl edit cm kubeadm-config -n kube-system
   ```
   Change the `imageRepository` value to the new repository. Make sure to retain the `ks8.gcr.io` prefix if necessary. After making this change, kubeadm will use the specified repository for downloading Kubernetes component images, but only after the next `upgrade` or `add_node` procedure.

2. **Update `cluster.yaml`**:
   Make sure to update the `imageRepository` in your `cluster.yaml` as well to avoid inconsistencies between the file and the actual cluster configuration.

3. **Update container runtime configuration**:
   You may need to change your container runtime configuration to ensure it works consistently with the new registry. This step is optional unless you want to configure an insecure registry.

   If you have a unified registry specified in `cluster.yaml` under the `registry` section, update it to point to the new repository address. Additionally, if there are container runtime configurations under the `cri` section, ensure they are aligned with the new registry, including configuring insecure access if needed.

4. **Apply changes**:
   After making these changes, run the `install` procedure with the `prepare.cri` task to update the container runtime configuration. This action restarts all containers in the cluster, which will make it temporarily unavailable.

   > **Warning**: Executing these actions will restart all pods in the cluster as part of the container runtime configuration changes. Ensure this downtime is acceptable before proceeding.

5. **Container runtime updates**:
   If you're using `containerd` as the container runtime, its version may also be updated during this process.

Once these steps are completed, your cluster will be ready to upgrade using the new image repository.

### Recommendations
Ensure the `imageRepository` is consistently updated in both `kubeadm-config` and `cluster.yaml`, and verify that the container runtime configuration is aligned with the new repository settings.

**Note**: Not applicable.

### Kubernetes Garbage Collector Doesn't Reclaim Disk Space

### Description
The Kubernetes garbage collector is failing to free up disk space, as indicated by error messages like:
```text
Apr 02 13:15:01 worker3 kubelet[1114]: E0402 13:15:01.809804    1114 kubelet.go:1302] Image garbage collection failed multiple times in a row: failed to garbage collect required amount of images. Wanted to free 966184140 bytes, but freed 0 bytes
```
Additionally, disk space usage is increasing, and pods are being evicted due to DiskPressure.

### Alerts
Not applicable.

### Stack trace(s)
Not applicable.

### How to resolve
The root cause of this issue is that the Kubernetes garbage collector only cleans up unused images and containers located under `/var/lib/docker`. It initiates cleanup when disk usage reaches the `image-gc-high-threshold` (default is 85%). Pods are evicted due to DiskPressure when the free disk space is less than `imagefs.available` (default is 15%).

If non-container files occupy the disk space and the garbage collector cannot free enough space, this error may occur.

To resolve this issue:
1. **Move `/var/lib/docker` to a separate disk** of reasonable size to free up space on the main disk.
2. **Adjust `image-gc-high-threshold`** to a value lower than 100 minus `imagefs.available`. For example, setting it to 80% ensures that garbage collection starts earlier.

The `image-gc-high-threshold` can be set as a kubelet flag in `/var/lib/kubelet/kubeadm-flags.env`. Ensure that its value is higher than `image-gc-low-threshold`, whose default is 80%. Here is an example of a `kubeadm-flags.env` file:
```bash
KUBELET_KUBEADM_ARGS="--cgroup-driver=systemd --network-plugin=cni --pod-infra-container-image=registry.k8s.io/pause:3.1 --kube-reserved cpu=200m,memory=256Mi --system-reserved cpu=200m,memory=512Mi --max-pods 250 --image-gc-high-threshold 80 --image-gc-low-threshold 70"
```

### Recommendations
- Regularly monitor disk space usage and garbage collection thresholds to prevent DiskPressure issues.


### Upgrade Procedure to v1.28.3 Fails on ETCD Step

### Description
During the upgrade from v1.28.0 (or v1.28.1, v1.28.2) to v1.28.3, the upgrade procedure fails at the ETCD step, showing the following error message:

```text
2023-11-10 11:56:44,465 CRITICAL        Command: "sudo kubeadm upgrade apply v1.28.3 -f --certificate-renewal=true --ignore-preflight-errors='Port-6443,CoreDNSUnsupportedPlugins' --patches=/etc/kubernetes/patches && sudo kubectl uncordon ubuntu && sudo systemctl restart kubelet"
```

In the `debug.log`, the following message is logged:
```text
2023-11-10 11:56:44,441 140368685827904 DEBUG [__init__.upgrade_first_control_plane]    [upgrade/apply] FATAL: fatal error when trying to upgrade the etcd cluster, rolled the state back to pre-upgrade state: couldn't upgrade control plane. kubeadm has tried to recover everything into the earlier state. Errors faced: static Pod hash for component etcd on Node ubuntu did not change after 5m0s: timed out waiting for the condition
```

### Alerts
Not applicable.

### Stack trace(s)
Not applicable.

### How to resolve
The root cause is that `kubeadm v1.28.0` adds default fields that are incompatible with `kubeadm v1.28.3`. To resolve this issue:

1. **Remove the following parts from the `etcd.yaml` manifest** on each control plane node in the cluster, one by one. The lines to remove are marked by `-`:

```yaml
apiVersion: v1
kind: Pod
...
spec:
  containers:
  - command:
      ...  
    image: registry.k8s.io/etcd:3.5.9-0
    imagePullPolicy: IfNotPresent
    livenessProbe:
      failureThreshold: 8
      httpGet:
        host: 127.0.0.1
        path: /health?exclude=NOSPACE&serializable=true
        port: 2381
        scheme: HTTP
      initialDelaySeconds: 10
      periodSeconds: 10
      successThreshold: 1
      timeoutSeconds: 15
    name: etcd
    resources:
      requests:
        cpu: 100m
        memory: 100Mi
    startupProbe:
      failureThreshold: 24
      httpGet:
        host: 127.0.0.1
        path: /health?serializable=false
        port: 2381
        scheme: HTTP
      initialDelaySeconds: 10
      periodSeconds: 10
      successThreshold: 1
      timeoutSeconds: 15
    terminationMessagePath: /dev/termination-log
    terminationMessagePolicy: File
    volumeMounts:
    - mountPath: /var/lib/etcd
      name: etcd-data
    - mountPath: /etc/kubernetes/pki/etcd
      name: etcd-certs
  dnsPolicy: ClusterFirst
  enableServiceLinks: true
  hostNetwork: true
  priority: 2000001000
  priorityClassName: system-node-critical
  restartPolicy: Always
  schedulerName: default-scheduler
  securityContext:
    seccompProfile:
      type: RuntimeDefault
  terminationGracePeriodSeconds: 30
...
```

2. **Wait for the ETCD to restart**.

3. **Run the upgrade procedure again** to complete the upgrade.

### Recommendations
Ensure you manually update the `etcd.yaml` manifest before retrying the upgrade to prevent compatibility issues with `kubeadm v1.28.3`.

**Note**: Not applicable.


## Numerous Generation of `Auditd` System

### Description
Numerous system messages are being generated on nodes, and they are processed in Graylog. These logs can quickly accumulate, as seen with the audit log files:

```text
-rw-------. 1 root root 1528411 aug 13 10:36 audit.log
-r--------. 1 root root 8388693 aug 13 10:35 audit.log.1
-r--------. 1 root root 8388841 aug 13 10:34 audit.log.2
-r--------. 1 root root 8388720 aug 13 10:32 audit.log.3
-r--------. 1 root root 8388785 aug 13 10:30 audit.log.4
```

### Alerts
Not applicable.

### Stack trace(s)
Not applicable.

### How to resolve
The root cause of the issue is the addition of new rules to `audit.rules` due to the update of the default.yaml configuration file. The default audit settings in Linux operating systems involve two files: `auditd.conf` and `audit.rules`. For example, the following rules have been added:

```text
-w /var/lib/docker -k docker 
-w /etc/docker -k docker 
-w /usr/lib/systemd/system/docker.service -k docker 
-w /usr/lib/systemd/system/docker.socket -k docker 
-w /etc/default/docker -k docker 
-w /etc/docker/daemon.json -k docker 
-w /usr/bin/containerd -k docker 
-w /usr/sbin/runc -k dockerks 
-w /usr/bin/dockerd -k docker
```

To resolve the issue, follow these steps:

1. **Modify the `auditd.conf` file**:
   - Set the maximum log file size and number of log files to limit excessive log generation:
   ```bash
   max_log_file = 8  # File size in megabytes
   num_logs = 5      # Number of generated log files
   ```

2. **Remove the added rules**:
   - Delete the added rules related to Docker from `predefined.rules`, located in `/etc/audit/rules.d`:
   ```bash
   -w /var/lib/docker -k docker 
   -w /etc/docker -k docker 
   -w /usr/lib/systemd/system/docker.service -k docker 
   -w /usr/lib/systemd/system/docker.socket -k docker 
   -w /etc/default/docker -k docker 
   -w /etc/docker/daemon.json -k docker 
   -w /usr/bin/containerd -k docker 
   -w /usr/sbin/runc -k dockerks 
   -w /usr/bin/dockerd -k docker
   ```

3. **Apply the new configuration**:
   After making the changes, apply the updated audit rules by restarting the `auditd` service:
   ```bash
   sudo service auditd restart
   ```

### Recommendations
Monitor audit logs to ensure that unnecessary rules are not being added, and adjust `auditd` settings to manage the size and retention of logs effectively.

**Note**: Not applicable.


## Failure During Installation on Ubuntu OS With Cloud-init

### Description
Installation failures can occur on Ubuntu when the `cloud-init` service is running simultaneously with `Kubemarine` procedures. These issues often arise due to conflicts during the updating of apt repositories.

### Alerts
Not applicable.

### Stack trace(s)
Not applicable.

### How to resolve
To avoid potential problems, if the operating system has just been installed on a VM, it is recommended to **wait approximately 10 minutes** before starting any `Kubemarine` procedures. This ensures that the `cloud-init` service has completed its initial setup.

You can check the current status of `cloud-init` and ensure it has finished its preparations using the following command:
```bash
cloud-init status
```

Wait for the service to complete before proceeding with the installation to avoid conflicts.

### Recommendations
- Verify the status of `cloud-init` after an OS installation to ensure the system is fully prepared before initiating any `Kubemarine` procedures.
- Delaying the start of `Kubemarine` by 10 minutes allows `cloud-init` to finish without interference.

**Note**: Not applicable.

## Troubleshooting an Installation That Ended Incorrectly

### Description
Sometimes the installation of Kubemarine may not complete correctly. For further analysis of the issue, Kubemarine provides functionality that collects information about the cluster installation before each procedure.

### Alerts
Not applicable.

### Stack trace(s)
Not applicable.

### How to resolve

To analyze the situation:
1. After entering the node, navigate to the path `/etc/kubemarine/kube_tasks`, where you will find logs that were collected during the installation process.
   
2. The logs are organized into a set of files, which include:
   ```bash
   data_time_initial_procedure
     cluster.yaml
     version
     dump/
       cluster_finalized.yaml
       cluster_precompiled.yaml
       cluster.yaml
       procedure_parameters
   ```

3. Review these files to try and identify the cause of the failed Kubemarine installation. Specifically, analyzing `cluster_finalized.yaml`, `cluster_precompiled.yaml`, and `procedure_parameters` may provide insights into what went wrong during the installation.

### Recommendations
Regularly check and review the logs in `/etc/kubemarine/kube_tasks` after any failed installation attempts to assist in identifying and resolving issues.

**Note**: Not applicable.


## Kubectl logs and kubectl exec fail

### Description
Attempts to retrieve pod logs or execute a command inside the container using `kubectl logs` and `kubectl exec` fail due to TLS-related errors. These errors occur because the kubelet server certificate is not approved in a cluster where self-signed certificates are not allowed for the kubelet server.

### Alerts
Not applicable.

### Stack trace(s)
```text
$ kubectl -n my-namespace logs my-pod
Error from server: Get "https://192.168.1.1:10250/containerLogs/my-namespace/my-pod/controller": remote error: tls: internal error
```
```text
$ kubectl -n my-namespace exec my-pod -- id
Error from server: error dialing backend: remote error: tls: internal error
```

### How to resolve
1. Perform the Certificate Signing Request (CSR) approval process by following the steps outlined in the maintenance guide.
2. Refer to the [Kubelet Server Certificate Approval](https://github.com/Netcracker/KubeMarine/blob/main/documentation/internal/Hardening.md#kubelet-server-certificate-approval) section for detailed instructions on how to approve the kubelet server certificate.

### Recommendations
Ensure that the cluster's certificate management process is aligned with the security policies. Regularly check the status of certificates to avoid such issues.

**Note**: Not applicable.

## OpenSSH server becomes unavailable during cluster installation on Centos 9

### Description
During cluster installation on Centos9 or Oracle Linux 9, the OpenSSH server becomes unavailable, leading to a failure in the installation process at the `kubemarine.system.reboot_nodes` stage. This issue is caused by a version mismatch between OpenSSL and OpenSSH, which results in OpenSSH being unable to start.

### Alerts
Not applicable.

### Stack trace(s)
```text
OpenSSL version mismatch. Built against 30000070, you have 30200010
sshd.service: Main process exited, code=exited, status=255/EXEPTION
sshd.service: Failed with result 'exit-code'.
Failed to start OpenSSH server daemon.
```

### How to resolve
1. To resolve this issue, update the OpenSSH server to ensure compatibility with the updated OpenSSL version.
2. Add the following upgrade section to the **cluster.yaml** file:
   ```yaml
   services:
     packages:
       upgrade:
         - openssh-server
   ```

3. This will ensure the OpenSSH server is upgraded along with OpenSSL, avoiding the version mismatch problem.

### Recommendations
- Ensure that critical services such as OpenSSH are upgraded when their dependencies, like OpenSSL, are updated.
- Test updates in a staging environment to catch compatibility issues before deployment.

**Note**: Not applicable.

## Packets loss during the transmission between nodes

### Description
Packets are lost during the transmission between nodes that are located in different subnets. It appears in retries of TCP sessions or inability to get the UDP packets in case of high network load. The root cause is in the IaaS level routers performance. Basically, routing works slower than switching.

### Alerts
Not applicable.

### Stack trace(s)
Not applicable.

### How to resolve
Reschedule the pods in cluster to displace the pods that create the significant network load to the nodes in the same subnet OR move all of the nodes in the cluster in the same subnet

### Recommendations
- Avoid routing between nodes in the same cluster in case of high network load

**Note**: Not applicable.
