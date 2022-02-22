This section provides troubleshooting information for Kubemarine and Kubernetes solutions.

- [KubeMarine Errors](#kubemarine-errors)
  - [KME0001: Unexpected exception](#kme0001-unexpected-exception)
  - [KME0002: Remote group exception](#kme0002-remote-group-exception)
  - [KME0003: Action took too long to complete and timed out](#kme0003-action-took-too-long-to-complete-and-timed-out)
  - [KME0004: There are no workers defined in the cluster scheme](#kme0004-there-are-no-workers-defined-in-the-cluster-scheme)
  - [KME0005: {hostname} is not a sudoer](#kme0005-hostname-is-not-a-sudoer)
- [Troubleshooting Tools](#troubleshooting-tools)
  - [etcdctl script](#etcdctl-script)
- [Troubleshooting Kubernetes Generic Issues](#troubleshooting-kubernetes-generic-issues)
  - [CoreDNS Responds with High Latency](#coredns-responds-with-high-latency)
  - [Namespace with terminating CR/CRD cannot be deleted. Terminating CR/CRD cannot be deleted](#namespace-with-terminating-crcrd-cannot-be-deleted-terminating-crcrd-cannot-be-deleted)
  - [Packets between nodes in different networks are lost](#packets-between-nodes-in-different-networks-are-lost)
  - [`kubectl apply` fails with error "metadata annotations: Too long"](#kubectl-apply-fails-with-error-metadata-annotations-too-long)
  - [`kube-apiserver` requests throttling](#kube-apiserver-requests-throttling)
  - [Long Recovery after a Node Goes Offline](#long-recovery-after-a-node-goes-offline)
- [Troubleshooting Kubemarine](#troubleshooting-kubemarine)
  - [Failures During Kubernetes Upgrade Procedure](#failures-during-kubernetes-upgrade-procedure)
  - [Numerous generation of auditd system messages ](#numerous-generation-of-auditd-system)
  - [Failing during installation on Ubuntu OS](#failing-during-installation-on-ubuntu-os)

# KubeMarine Errors

This section lists all known errors with explanations and recommendations for their fixing. If an 
error occurs during the execution of any of these procedures, you can find it here.


## KME0001: Unexpected exception

```
FAILURE - TASK FAILED xxx
Reason: KME001: Unexpected exception
Traceback (most recent call last):
  File "/home/centos/repos/kubemarine/kubemarine/src/core/flow.py", line 131, in run_flow
    task(cluster)
  File "/home/centos/repos/kubemarine/kubemarine/install", line 193, in deploy_kubernetes_init
    cluster.nodes["worker"].new_group(apply_filter=lambda node: 'master' not in node['roles']).call(kubernetes.init_workers)
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

This error occurs in case of an unexpected exception at runtime and does not yet have a classifying 
code.

To fix it, first try checking the nodes and the cluster with 
[IAAS checker](Kubecheck.md#iaas-procedure) and [PAAS checker](Kubecheck.md#paas-procedure). If you 
see failed tests, try fixing the cause of the failure. If the error persists, try to inspect the 
stacktrace and come to a solution yourself as much as possible. 

If you still can't resolve this error yourself, start 
[a new issue](https://github.com/Netcracker/KubeMarine/issues/new) and attach a description of the 
error with its stacktrace. We will try to help as soon as possible.

If you were able to solve the problem yourself, let us know about it and your solution by 
[opening a new PR](https://github.com/Netcracker/KubeMarine/pulls). Our team will appreciate it!


## KME0002: Remote group exception

Shell error:

```
FAILURE!
TASK FAILED xxx
KME0002: Remote group exception
10.101.10.1:
	Encountered a bad command exit code!
	
	Command: 'apt install bad-package-name'
	
	Exit code: 127
	
	Stdout:
	
	
	
	Stderr:
	
	bash: apt: command not found
```

Hierarchical error:

```
FAILURE!
TASK FAILED xxx
KME0002: Remote group exception
10.101.10.1:
	KME0003: Action took too long to complete and timed out
```

An error indicating an unexpected runtime bash command exit on a remote cluster host. This error 
occurs when a command is terminated unexpectedly with a non-zero error code.

The error prints the status of the command execution for each node in the group on which the bash command 
was executed. The status can be a correct result (shell results), a result with an error 
(shell error), as well as a hierarchical KME with its own code.

To fix it, first try checking the nodes and the cluster with 
[IAAS checker](Kubecheck.md#iaas-procedure) and [PAAS checker](Kubecheck.md#paas-procedure). If you 
see failed tests, try fixing the cause of the failure. Make sure that you do everything according to 
the instructions in the correct sequence and correctly fill the inventory and other dependent
files. If the error persists, try to figure out what might be causing the command to fail on remote 
nodes and fix by yourself as much as possible.

If you still can't resolve this error yourself, start 
[a new issue](https://github.com/Netcracker/KubeMarine/issues/new) and attach a description of the 
error with its stacktrace. We will try to help as soon as possible.


## KME0003: Action took too long to complete and timed out

```
FAILURE!
TASK FAILED xxx
KME0002: Remote group exception
10.101.10.1:
	KME0003: Action took too long to complete and timed out
```

An error that occurs when a command did not have time to execute at the specified time.

The error can occur if there is a problem with the remote hypervisor or host hanging, if the 
command executable hangs, or if the SSH-connection is unexpectedly disconnected or other network 
problems between the deployer node and the cluster.

The longest possible timeout for the command is 2700 seconds (45 minutes).

To resolve this error, check all of the listed items that may hang and manually fix the hang by 
rebooting the hypervisor or node, fixing the environment or settings of the executable, updating it,
fixing the network channel, as well as any other actions that, in your opinion, should fix the 
frozen stage of the procedure. It will be useful to check the cluster with 
[IAAS checker](Kubecheck.md#iaas-procedure) to detect problems with network connectivity.


## KME0004: There are no workers defined in the cluster scheme

```
FAILURE!
KME0004: There are no workers defined in the cluster scheme
```

An error related with the absence of any worker role in the inventory file. The error occurs before
the payload is executed on the cluster.

To fix it, you need to either specify new nodes with the `worker` role, or add the `worker` role to 
the existing masters nodes.

An example of specifying different nodes with separate `master` and `worker` roles is as follows.

```yaml
- address: 10.101.1.1
  internal_address: 192.168.101.1
  name: master-1
  roles:
  - master
- address: 10.101.1.2
  internal_address: 192.168.101.2
  name: worker-1
  roles:
  - worker
```

An example of specifying multiple `master` and `worker` roles for a single node is as follows.

```yaml
- address: 10.101.1.1
  internal_address: 192.168.101.1
  name: master-1
  roles:
  - master
  - worker
```

**Note**: Masters with a `worker` role remain as control planes, however, they start scheduling
applications pods.


## KME0005: {hostname} is not a sudoer

```
FAILURE!
TASK FAILED prepare.check.sudoer
KME0005: 10.101.1.1 is not a sudoer
```

The error reports that the specified node does not have superuser rights. The error occurs 
before the payload is executed on the cluster when running the `install` or `add_node` procedure.

To fix this, add a connection user to the sudoer group on the cluster node. 

An example for Ubuntu (reboot required) is as given below.

```bash
sudo adduser <username> sudo
```


# Troubleshooting Tools

This section describes the additional tools that Kubemarine provides for convenient troubleshooting of various issues.

## etcdctl script

This script allows you to execute `etcdctl` queries without installing an additional binary file and setting up a connection. This file is installed during the `prepare.thirdparties` installation task on all masters and requires root privileges.

To execute a command through this script, make sure you meet all the following prerequisites:

* You run the command from the master node with root privileges.
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
1. If the Kubernetes cluster is dead, then try to parse the `/etc/kubernetes/manifests/etcd.yaml` file and launch the ETCD container.

Since the command is run from a container, this imposes certain restrictions. For example, only certain volumes are mounted to the container. Which one it is, depends directly on the version and type of installation of ETCD and Kubernetes, but as a rule it is:

* `/var/lib/etcd`:`/var/lib/etcd`
* `/etc/kubernetes/pki`:`/etc/kubernetes/pki`

# Troubleshooting Kubernetes Generic Issues

This section provides troubleshooting information for generic Kubernetes solution issues, which are not specific to Kubemarine installation.

## CoreDNS Responds with High Latency

**Symptoms**: CoreDNS responds with some delay.

**Root Cause**: With a large volume of the cluster or applications in it, the load on the CoreDNS can increase.

**Solution**: To fix this problem, it is recommended to increase the number of replicas using the following command:
 
```
# kubectl scale deployments.apps -n kube-system coredns --replicas=4
```
 
Choose the number of replicas at your discretion. In addition to increasing the replicas, it is recommended to use anti-affinity rules to reassign all CoreDNS pods to each node without any duplicates.

## Namespace with terminating CR/CRD cannot be deleted. Terminating CR/CRD cannot be deleted

**Symptoms**: A namespace containing a terminating `CustomResource` cannot be deleted, or simply `CustomResource` in some namespace hangs infinitely in the terminating status and cannot be deleted.

**Root Cause**: This issue occurs when `CustomResource` has finalizers that are not deleted. This could happen because the controller that manages the `CustomResource` is not operational, for example, if the controller is deleted. As a result, the controller cannot handle and remove finalizers.

`CustomResources` with non-empty finalizers are never deleted.

**Solution**: There are two possible solutions to this issue:

* If the controller is just temporarily unavailable, then `CustomResource` is deleted as soon as the controller starts running. You just have to make the controller operational. This is the recommended approach as the controller is able to perform on-delete logic.
* If the controller is removed, or you do not want to deal with an unavailable controller, remove `CustomResource` by manually deleting its finalizers. This approach is not recommended as the required on-delete logic for `CustomResource` is not executed by the controller.

To manually delete a finalizer for `CustomResource`, execute the following command on one of the master nodes:

```bash
kubectl patch <cr-singular-alias/cr-name> -p '{"metadata":{"finalizers":[]}}' --type=merge
```

For example:

```bash
kubectl patch crontab/my-new-cron-object -p '{"metadata":{"finalizers":[]}}' --type=merge
```

## Packets between nodes in different networks are lost

**Symptoms**: Some packets between pods running on nodes in different networks are lost. DNS requests are also lost on the network. 

**Root Cause**: Default kubernetes installation uses calico network plugin and set ipip mode with CrossSubnet. In that case all packets between pods running on nodes in one networks go to each other directly, but packets between pods running on nodes in two or more networks go to each other by tunnel. As described in [calico documentation](https://docs.projectcalico.org/networking/mtu) MTU on calico tunl interfaces should be less by 20 than MTU on main network interface.

**Solution**: To change MTU size to required value run following command on any master node:

```
# kubectl patch configmap/calico-config -n kube-system --type merge -p '{"data":{"veth_mtu": "1440"}}'
```

where:
  - **1440** is the size of MTU. For MTU 1450 on interface eth0 you should set MTU size 1430 for calico-config.


After updating the ConfigMap, perform a rolling restart of all calico/node pods. For example:

```
# kubectl rollout restart daemonset calico-node -n kube-system
```

It changes MTU value only for new pods. To apply new MTU value for all pods in the cluster you should restart all pods or nodes one by one.

## `kubectl apply` fails with error "metadata annotations: Too long"

**Symptoms**: The `kubectl apply` command fails with an error having "metadata annotations: Too long" message. 

**Root Cause**: This issue happens when you try to apply a resource with a very large configuration.
The problem is that `kubectl apply` tries to save the new configuration to the `kubectl.kubernetes.io/last-applied-configuration` annotation. If the new configuration is too big, it cannot fit the annotation's size limit.
The maximum size cannot be changed, so `kubectl apply` is unable to apply large resources.

**Solution**: Use `kubectl create` instead of `kubectl apply` for large resources.

## `kube-apiserver` requests throttling

**Symptoms**: Different services start receiving “429 Too Many Requests” HTTP error even though kube-apiservers can take more load.
 
**Root Cause**: Low rate limit for `kube-apiserver`.

**Solution**: Raise the rate limit for the `kube-apiserver` process using `--max-requests-inflight` and `--max-mutating-requests-inflight` options.
* `--max-requests-inflight` is the maximum number of non-mutating requests. The default value is 400.
* `--max-mutating-requests-inflight` is the maximum number of mutating requests. The default value is 200.

`kube-apiserver` configration file is stored in /etc/kubernetes/manifests/kube-apiserver.yaml. This file should be changed 
on all masters. Also, the configuration map `kubeadm-config` from kube-system namespace should have the same values 
in `apiServer` section.

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

## Long Recovery after a Node Goes Offline

**Symptoms**: When for any reason a cluster node goes offline pods from this node will be redeployed in almost 6 minutes. For some installations it might be too long and this time needs be reduced.

**Root Cause**: When a node goes offline kubernetes needs time to discover that the node is unavalable (up to 10 seconds), then waits for the node returns or a timeout expires (40 seconds), then marks pods at this node as to be deleted and wait for the situation recovers or a timeout expires (5 minutes). After that the pods are being redeployed to healthy nodes.

**Solution**: Reduce timeouts related to a node status discovery and pods eviction.

It can be done by the following variables tuning:
- `nodeStatusUpdateFrequency` - a kubelet's variable, meaning the frequency that kubelet computes node status and posts it to master. Default value is 10s. It should be twice more than `node-monitor-period`.
- `node-monitor-period` - a kube-controller-manager's variable meaning the period for syncing NodeStatus in NodeController. Default value is 5s. It should be twice less than `nodeStatusUpdateFrequency`.
- `node-monitor-grace-period` - a kube-controller-manager's variable meaning the amount of time which a running Node is allowed to be unresponsive before marking it unhealthy. Default value is 40s. Must be (N-1) times more than kubelet's `nodeStatusUpdateFrequency`, where N means number of retries allowed for kubelet to post node status. Currently N is hardcoded to 5. 
- `pod-eviction-timeout` - a kube-controller-manager's variable meaning the grace period for deleting pods on failed nodes. Default value is 5min.

These variables can be redefined in cluster.yaml during cluster deploy or upgrade. For example:

```
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

The exact numbers should be chosen according to the environment state. If network or hosts may be unstable, these values should cover short nodes unavailability without pods redeployment, otherwise often redeployment may cause significant load increase and the cluster instability.

At working clusters these variables can be adjusted manually by updating `/var/lib/kubelet/config.yaml` (for kubelet, at all the nodes) and `/etc/kubernetes/manifests/kube-controller-manager.yaml` (for controller-manager, at the masters).


## `kube-controller-manager` unable to sync caches for garbage collector

**Symptoms**: The following errors in the `kube-controller-manager` logs:
```
E0402 10:52:00.858591 8 shared_informer.go:226] unable to sync caches for garbage collector
E0402 10:52:00.858600 8 garbagecollector.go:233] timed out waiting for dependency graph builder sync during GC sync (attempt 16)
I0402 10:52:00.883519 8 graph_builder.go:272] garbage controller monitor not yet synced 
```
 
**Root Cause**: The problem may be related to etcd I/O performance and lack of CPU resources for kubeapi (kubernetes API uses a lot of CPU resources) and etcd. The CPU resource saturation affects master API and etcd cluster and it also affects the garbage collector of the master controller manager tasks due to sync failure. 

**Solution**: Increase resources for master nodes to match the load on the kube-api or reduce the load on the kube-api.

## etcdctl compaction and defragmentation

**Symptoms**: The following error in the `etcd` pod logs:
```
etcdserver: mvcc: database space exceeded
etcdserver: no space
```

Also note that if the etcd database is 70% of the default storage size, the etcd database require defragmentation. The [default storage size](https://etcd.io/docs/v3.5/dev-guide/limit/#storage-size-limit) limit is 2GB.

**Root Cause**: After the compacting procedure leaves gaps in the etcd database. This fragmented space is available for use by etcd, but is not available to the host file system. You must defragment the etcd database to make this space available to the filesystem.
After the compacting procedure leaves gaps in the etcd database. This fragmented space is available for use by etcd, but is not available to the host file system. You must defragment the etcd database to make this space available to the filesystem.

Compaction is performed automatically every 5 minutes. This value can be overridden using the `--etcd-compaction-interval` flag for kube-apiserver.

**Solution**: To fix this problem, it is recommended to run defragmentation for etcd database sequentially for each cluster member. Defragmentation is issued on a per-member so that cluster-wide latency spikes may be avoided.
To run defragmentation for etcd member use the following command:
```
# etcdctl defrag --endpoints=ENDPOINT_IP:2379
```

To run defragmentation for all cluster members list all endpoints sequentially
```
# etcdctl defrag --endpoints=ENDPOINT_IP1:2379, --endpoints=ENDPOINT_IP2:2379, --endpoints=ENDPOINT_IP3:2379
```
`ENDPOINT_IP` is the internal IP address of the etcd endpoint.

> **Note**: The defragmentation to a live member blocks the system from reading and writing data while rebuilding its states. It is not recommended to run defragmentation for all etcd members at the same time.

## etcdctl defrag return context deadline exceeded

**Symptoms**: After running the defrag procedure for etcd database the following error may occur:
```
"error":"rpc error: code = DeadlineExceeded desc = context deadline exceeded"}
Failed to defragment etcd member
```

**Root Cause**: The default timeout for short running command is 5 seconds, and this is not enough.

**Solution**: If you get a similar error then use an additional `--command-timeout` flag to run the command:
```
# etcdctl defrag --endpoints=ENDPOINT_IP:2379 --command-timeout=30s
```

# Troubleshooting Kubemarine

This section provides troubleshooting information for Kubemarine-specific or installation-specific issues.

## Failures During Kubernetes Upgrade Procedure

### Upgrade procedure failure, upgrade not completed

**Symptoms**: The `upgrade` procedure fails at some point and leaves the upgrade process in an incomplete state.

**Root cause**: Any error during the `upgrade` procedure could cause an upgrade procedure failure.

**Solution**: First of all, it is required to find the root cause of the failure and fix it. You can check other troubleshooting sections in this guide regarding the issues during the upgrade. 

After the cause of the failure is fixed, you need to run the `upgrade` procedure once again to complete the upgrade. However, it is very important to check the status of the upgrade process before restarting the procedure because it may be required to change the procedure parameters like `cluster.yaml` and procedure inventory. 

For example, imagine you are doing the following upgrade: `1.16.12 -> 1.17.7 -> 1.18.8`. 
In this case, if the upgrade fails on version `1.18.8`, but is completed for version `1.17.7`, you have to update `cluster.yaml` with the latest information available in the regenerated inventory (`cluster.yaml` is regenerated after each minor version upgrade) and also remove version `1.17.7` from the procedure inventory. It is absolutely fine to retry upgrades for version `X.Y.Z`, but only until the moment the upgrade starts for next version `X.Y+1.M`. It is incorrect to start upgrade to version `1.17.7` after the upgrade to version `1.18.8` is started.

### Cannot drain node because of PodDisruptionBudget

**Symptoms**: The `upgrade` procedure fails during node drain because of PodDisruptionBudget (PDB) limits.

**Root cause**: Kubernetes is unable to drain a pod because draining the pod violates PDB rules configured by some application.

**Solution**: Since the Kubernetes version 1.18, there is an option to ignore PDB rules during upgrades using `disable-eviction`. You can configure this option in the upgrade procedure. This option is enabled by default.

If you face an issue with PDB rules during the upgrade on Kubernetes versions lower than 1.18, then temporarily change PDB limits to lower values, so that pods could be drained. After that you can run the `upgrade` procedure once again. After the upgrade, you have to return the PDB limits to the previous value.

### Cannot drain node because of pod stuck in "Terminating" status

**Symptoms**: The `upgrade` procedure fails during node drain because of the pod stuck in the "Terminating" status.

**Root cause**: There could be many different reasons for pod being stuck in the "Terminating" status. Try to check the pod events to gather more details. Delete the "Terminating" pod to continue the upgrade.

**Solution**: To resolve the issue with pod stuck in the "Terminating" status, perform the following steps:

1. Try to forcefully delete the terminating pod using the command: `kubectl delete pod <PODNAME> --grace-period=0 --force --namespace <NAMESPACE>`.
2. If force delete does not help, try to reboot the node on which the pod is stuck in the "Terminating" status.

After the "Terminating" pod is deleted, run the `upgrade` procedure once again.

### Etcd pod customizations are missing after upgrade

**Symptoms**: After an upgrade, you may notice that your etcd customizations are not present in the `/etc/kubernetes/manifests/etcd.yaml` file.

**Root cause**: During the upgrade, etcd configuration is re-generated by kubeadm from its own configuration in `kubeadm-config` config map in `kube-system` namespace. Your customizations are missing in this config map.

**Solution**: You need to put your customizations not only to the etcd pod manifest in `/etc/kubernetes/manifests/etcd.yaml` file, but also to `kubeadm-config` config map in `kube-system` namespace. 
For example, if you want to increase etcd snapshot count from 10000 to 10001, you need to also modify `kubeadm-config` config map as following:

```yaml
data:
  ClusterConfiguration: |
    etcd:
      local:
        extraArgs:
          snapshot-count: "10001"
```

Note that the key has the same name as the etcd argument. The value should be quoted. 
After the upgrade, this results in following etcd argument (among others):

```yaml
spec:
  containers:
  - command:
    - etcd
    - --snapshot-count=10001
```

Note that these arguments are added by kubeadm during the upgrade only, they will not be added automatically.
It means that you should manually add your customization to both the `/etc/kubernetes/manifests/etcd.yaml` file and the `kubeadm-config` config map.

If everything is done correctly, all of your etcd customizations persist among Kubernetes upgrades.

### Kubernetes image repository does not change during upgrade

**Symptoms**: You expect Kubernetes to use a new repository during and after an upgrade, 
but Kubernetes keeps using the old image repository. Kubernetes may fail to find images and the upgrade fails.

**Root cause**: During an upgrade procedure, the kubeadm cluster configuration is not changed by `kubemarine`, 
particularly there is no way to change the Kubernetes image repository automatically during an upgrade using `kubemarine`.

**Solution**: You have to change the image repository manually in the kubeadm configuration and container runtime configuration. You have to modify `cluster.yaml` too.

To edit the kubeadm configuration, use the following command:

```bash
kubectl edit cm kubeadm-config -n kube-system
```

Here, change the `imageRepository` value to the new one, make sure to keep the `ks8.gcr.io` prefix if needed.
After these changes, kubeadm uses a new specified repository for downloading Kubernetes component images, 
but only after the `upgrade` or `add_node` procedure (for new nodes). 
Do not forget to change `imageRepository` in your `cluster.yaml` too, so that there are no inconsistencies
between `cluster.yaml` and the actual cluster configuration.

You may also need to change your container runtime configuration to work correctly and consistently with the new registry.

**Warning**: Executing the following actions restarts all pods in the cluster because the container runtime configuration changes.
These actions are actually optional, you need to execute them only if you want to use an insecure registry.

If you have global unified registry specified in the `cluster.yaml` under the `registry` section, then change it to point to the new repository address.
If you have container runtime configurations under the `cri` section in `cluster.yaml`, then make sure they are consistent with your new registry.
You may need to not only change registry address, but also configure insecure access.
Do not remove the old registry from your container runtime configuration as it could still be used for some images.
After these changes, you need to run the `install` procedure with the `prepare.cri` task to update the container runtime configuration. 
This restarts all containers in the cluster making it unavailable for some time.
If you use `containerd` as the container runtime, its version may also be updated.

After making these changes, your cluster should be ready to upgrade using the new image repository.

### Kubernetes garbage collector doesn't reclaim disk space

**Symptoms**: There are error messages in the log file like the following:

```
Apr 02 13:15:01 worker3 kubelet[1114]: E0402 13:15:01.809804    1114 kubelet.go:1302] Image garbage collection failed multiple times in a row: failed to garbage collect required amount of images. Wanted to free 966184140 bytes, but freed 0 bytes
```

Also, the disk space usage is increasing, and pods are being evicted due to DiskPressure.

**Root cause**: Kubernetes garbage collector cleans up only unused images and containers which are located under `/var/lib/docker`. It starts cleaning up when the disk usage is equal or above `image-gc-high-threshold` (The default value is 85%).
The pods' eviction due to DiskPressure starts when the free disk space is less than `imagefs.available` (The default value is 15%).
If other files except images and containers use the disk so that GC cannot free enough space, such an error may happen.

**Solution**: Move /var/lib/docker to a separate disk of reasonable size. Also setting `image-gc-high-threshold` to a value lower than 100-`imagefs.available` may help.

`image-gc-high-threshold` may be set as a kubelet flag in /var/lib/kubelet/kubeadm-flags.env. Keep in mind that its value should be higher than `image-gc-low-threshold`, whose default value is 80%. An example of kubeadm-flags.env file:

```
KUBELET_KUBEADM_ARGS="--cgroup-driver=systemd --network-plugin=cni --pod-infra-container-image=k8s.gcr.io/pause:3.1 --kube-reserved cpu=200m,memory=256Mi --system-reserved cpu=200m,memory=512Mi --max-pods 250 --image-gc-high-threshold 80 --image-gc-low-threshold 70"
```

## Numerous generation of `auditd` system 

**Symptoms**: Generation of numerous system messages on nodes and their processing in graylog:

```
-rw-------. 1 root root 1528411 aug 13 10:36 audit.log
-r--------. 1 root root 8388693 aug 13 10:35 audit.log.1
-r--------. 1 root root 8388841 aug 13 10:34 audit.log.2
-r--------. 1 root root 8388720 aug 13 10:32 audit.log.3
-r--------. 1 root root 8388785 aug 13 10:30 audit.log.4

```


**Root cause**: The reason for generating numerous messages is to add new rules to`audit.rules`.This is due to the update of the default.yaml configuration file.The default audit settings on Linux operating systems are two files: audit.d.conf and audit.rules
```
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


**Solution**: The solution to this problem is to modify the configuration files of the auditd daemon. 

1- Modifying the settings for the auditd.conf file
```
max_log_file = 8  <- Generated file size in megabytes
num_logs = 5 <- Number of generated files
```
2- Removing added rules
```
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

Rules are deleted in predefined.rules, which is located on this path /etc/audit/rules.d 

**After all the manipulations, you need to apply the new configuration with the command** `sudo service auditd restart`

## Failing during installation on Ubuntu OS with cloud-init

### Issues related to updating apt repositories list
 
* In the case of Ubuntu, difficulties may arise when the `cloud-init` and the `Kubemarine` work at the same time, in order to avoid potential problems, it is recommended that if the OS is just installed on the VM, do not start any `Kubemarine` procedures for ~10 minutes, so that the `cloud-init` service can finish its preparations. 
    * You can find out the current status of `cloud-init` and wait on completion by using the command below:
    ```bash
    cloud-init status
    ```
