# Kubemarine

Kubemarine is an open source, lightweight and powerful management tool built for end-to-end Kubernetes cluster deployment and maintenance. It's applicable for many purposes like simple and quick onboarding Kubernetes on local and production environments in different HA schemes depending on your aims, budget and capabilities. Together with simplicity Kubemarine can be very flexible and customizable tool covering specific configurability cases on both deployment and maintenance stages. This library provides powerfull CLI commands, as well as can be customized via Python extension API.

## Highlights
- Easy to use
- Many procedures supported:
  - [install](documentation/Installation.md#)
  - [add_node](documentation/Maintenance.md#add-node-procedure)
  - [remove_node](documentation/Maintenance.md#remove-node-procedure)
  - [upgrade](documentation/Maintenance.md#upgrade-procedure)
  - [backup](documentation/Maintenance.md#backup-procedure)
  - [restore](documentation/Maintenance.md#restore-procedure)
  - [check_iaas](documentation/Kubecheck.md#iaas-procedure)
  - [check_paas](documentation/Kubecheck.md#paas-procedure)
  - [manage_psp](documentation/Maintenance.md#manage-psp-procedure)
- [Single cluster inventory](documentation/Installation.md#configuration) for all operations, highly customizable
- Default values of all parameters in configurations with a minimum of required parameters
- [Control planes balancing](documentation/Installation.md#full-ha-scheme) with external balancers and VRRP
- Ability to [resume or skip specific task](documentation/Installation.md#tasks-list-redefinition) without re-running entire pipeline
- [Pre-built plugins](documentation/Installation.md#predefined-plugins) out of the box and [custom plugins](documentation/Installation.md#custom-plugins-installation-procedures) support
- Support for [executing in closed environments](documentation/Installation.md#installation-without-internet-resources) with private registries
- Extended [logging](documentation/Logging.md), configs [dumping](documentation/Installation.md#dump-files)
- Build supported as a package, container and binary
- Package extension with [open extension API](documentation/PackageExtension.md)
- Support different deployment schemes (all-in-one, mini-HA, HA, etc.)


## Kubemarine CLI Installation
Proceed the following steps to install Kubemarine manually on your environment:
1. Install latest [python3](https://www.python.org/downloads/)
2. Upgrade pip:
   ```bash
   python3 -m pip install --upgrade pip
   ```
3. Ensure your environment meets [Deployment Node Prerequisites](documentation/Installation.md#prerequisites-for-deployment-node)
4. [Download the latest release](https://github.com/netcracker-technology/kubemarine/releases) or clone the repo:
   ```bash
   git clone https://github.com/netcracker-technology/kubemarine.git
   ```
5. Unpack project from archive if required:
   ```bash
   tar xzvf X.X.X.tar.gz
   ```
6. Navigate to project directory:
   ```bash
   cd kubemarine
   ```
7. Install Python dependencies:
   ```bash
   python3 -m pip install -r requirements.txt
   ```
8. Optionally add Kubemarine to PATH.
   You can do this by adding symlink to `/usr/local/bin`:
   ```bash
   sudo ln -s $(pwd)/bin/kubemarine /usr/local/bin/kubemarine
   sudo chmod +x /usr/local/bin/kubemarine
   ```
   Alternatively, if you do not have root privileges, you can update your PATH in *rc file. Example:
   ```bash
   echo "export PATH=\$PATH:$(pwd)/bin" >> ~/.bashrc
   source ~/.bashrc
   ```
   If you don't want to add something to path, you can execute the Kubemarine directly from `bin` location:
   ```bash
   cd bin
   ```
10. Now you can proceed to run Kubemarine! Try the following:
    ```bash
    kubemarine help
    ```

**Note:** building from [Dockerfile](Dockerfile) is also available.

**Note:** Kubemarine debugging available via `kubemarine/__main__.py`.

## Running Cluster Installation
Proceed the following steps to install Kubernetes cluster using Kubemarine:
1. Prepare your VMs or bare-metal machines according to [Recommended Hardware Requirements](documentation/Installation.md#recommended-hardware-requirements) and selected [Deployment Scheme](documentation/Installation.md#deployment-schemes). Make sure the nodes meet [Cluster Nodes Prerequisites](documentation/Installation.md#prerequisites-for-cluster-nodes)
2. Create inventory file `cluster.yaml` and describe your env and everything should be configured. See [inventory configs available](documentation/Installation.md#configuration) and [examples](examples/cluster.yaml). No need to fill in all the parameters that are available, it is enough to specify the minimal identification data about the nodes where you want to install the cluster, for example:
   ```yaml
   node_defaults:
     keyfile: "/home/username/.ssh/id_rsa"
     username: "centos"

   vrrp_ips:
     - 192.168.0.250

   nodes:
     - name: "k8s-master-1"
       address: "10.101.0.1"
       internal_address: "192.168.0.1"
       roles: ["balancer", "master", "worker"]
     - name: "k8s-master-2"
       address: "10.101.0.2"
       internal_address: "192.168.0.2"
       roles: ["balancer", "master", "worker"]
     - name: "k8s-master-3"
       address: "10.101.0.3"
       internal_address: "192.168.0.3"
       roles: ["balancer", "master", "worker"]

   cluster_name: "k8s.example.com"
   ```
5. Move `cluster.yaml` to the directory, where Kubemarine installed
6. Start installation:
   ```bash
   kubemarine install
   ```

See [other guides](#documentation) for more info.

## Documentation
The following documents and tutorials are available:
- [Installation](documentation/Installation.md)
- [Maintenance](documentation/Maintenance.md)
- [Troubleshooting](documentation/Troubleshooting.md)
- [Kubecheck](documentation/Kubecheck.md)
- [Logging](documentation/Logging.md)

Also check out the following inventory examples we have prepared:
- [cluster.yaml](examples/cluster.yaml)
- [procedure.yaml](examples/procedure.yaml)

## Issues, Questions
If you have any problems while working with Kubemarine, feel free to open us a [new issue](https://github.com/netcracker-technology/kubemarine/issues) or even [PR](https://github.com/netcracker-technology/kubemarine/pulls) with related changes.
Follow the process outlined in the Stack Overflow [MCVE](https://stackoverflow.com/help/mcve) document and provide reproducible example.

## Changelog
Detailed changes for each release are documented in the [release notes](https://github.com/netcracker-technology/kubemarine/releases).

## License
[Apache License 2.0](LICENSE)
