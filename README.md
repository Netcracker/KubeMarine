![Kubemarine_1280х640_3_JPEG](https://user-images.githubusercontent.com/5212888/162978291-63d55f19-7dc0-4126-ad39-cd69191e7e19.jpg)
[![GitHub stars](https://img.shields.io/github/v/release/Netcracker/Kubemarine)](https://github.com/Netcracker/KubeMarine/releases)
[![GitHub stars](https://img.shields.io/badge/contributions-welcome-orange.svg)](https://github.com/Netcracker/KubeMarine/blob/main/CONTRIBUTING.md)

# Kubemarine

Kubemarine is an open source, lightweight and powerful management tool built for end-to-end Kubernetes cluster deployment and maintenance. It is applicable for many purposes like simple and quick onboarding Kubernetes on local and production environments in different HA schemes depending on your aims, budget, and capabilities. Together with simplicity, Kubemarine can be a very flexible and customizable tool covering specific configurability cases on both deployment and maintenance stages. This library provides powerful CLI commands, as well as can be customized using a Python extension API.

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
  - [migrate_kubemarine](documentation/Maintenance.md#kubemarine-migration-procedure)
  - [manage_psp](documentation/Maintenance.md#manage-psp-procedure)
  - [manage_pss](documentation/Maintenance.md#manage-pss-procedure)
  - [cert_renew](documentation/Maintenance.md#certificate-renew-procedure)
  - [migrate_cri](documentation/Maintenance.md#migration-cri-procedure)
- [Single cluster inventory](documentation/Installation.md#configuration) for all operations, highly customizable
- Default values of all parameters in configurations with a minimum of required parameters
- [Control planes balancing](documentation/Installation.md#full-ha-scheme) with external balancers and VRRP
- Ability to [resume or skip specific task](documentation/Installation.md#tasks-list-redefinition) without re-running entire pipeline
- [Pre-built plugins](documentation/Installation.md#predefined-plugins) out of the box and [custom plugins](documentation/Installation.md#custom-plugins-installation-procedures) support
- Support for [executing in closed environments](documentation/Installation.md#installation-without-internet-resources) with private registries
- Extended [logging](documentation/Logging.md), configs [dumping](documentation/Installation.md#dump-files)
- Build supported as a package, container, and binary
- Package extension with [open extension API](documentation/PackageExtension.md)
- Support different deployment schemes (all-in-one, mini-HA, HA, and so on)

## Kubemarine Binary Installation
Proceed the following steps to install Kubemarine  on your environment:
1. Download the binary file for your system from the latest [release](https://github.com/Netcracker/KubeMarine/releases)
2. Move binary kubemarine to a separate folder 
3. Now you can proceed to run Kubemarine! Try the following:
   
   Linux:
   ```bash
   kubemarine help
   ```


## Kubemarine CLI Installation
To install Kubemarine manually on your environment:
1. Install the latest [python3](https://www.python.org/downloads/)
2. Upgrade pip.

   Linux / MacOS:
   ```bash
   python3 -m pip install --upgrade pip
   ```
   Windows:
   ```bash
   python -m pip install --upgrade pip
   ```
3. Ensure your environment meets the [Deployment Node Prerequisites](documentation/Installation.md#prerequisites-for-deployment-node).
4. [Download the latest release](https://github.com/netcracker/kubemarine/releases) or clone the repository:
   ```bash
   git clone https://github.com/netcracker/kubemarine.git
   ```
5. Unpack the project from the archive if required:
   ```bash
   tar xzvf X.X.X.tar.gz
   ```
6. Navigate to the project directory:
   ```bash
   cd kubemarine
   ```
7. Install Python dependencies.

   Linux / MacOS:
   ```bash
   python3 -m pip install -r requirements.txt
   ```
   Windows:
   ```bash
   python -m pip install -r requirements_nt.txt
   ```
8. If you don't want to add something to PATH, you can execute Kubemarine directly from the `bin` location:
   ```bash
   cd bin
   ```
   Alternatively, add Kubemarine to PATH.
   On Linux / MacOS, you can do this by adding symlink to `/usr/local/bin` being in the root directory of Kubemarine:
   ```bash
   sudo ln -s $(pwd)/bin/kubemarine /usr/local/bin/kubemarine
   sudo chmod +x /usr/local/bin/kubemarine
   ```
   If you do not have root privileges, you can update your PATH in *rc file. Example:
   ```bash
   echo "export PATH=\$PATH:$(pwd)/bin" >> ~/.bashrc
   source ~/.bashrc
   ```
   On Windows, it is recommended to change PATH variable only through control panel.
   To do that, type *Edit the system environment variables* in Search box.
9. Now you can proceed to run Kubemarine. Try the following:
    ```bash
    kubemarine help
    ```

**Note**: Building from [Dockerfile](Dockerfile) is also available.


**Note:** Kubemarine debugging available via `kubemarine/__main__.py`.


## Running Cluster Installation
To install a Kubernetes cluster using Kubemarine:
1. Prepare your VMs or bare-metal machines according to [Recommended Hardware Requirements](documentation/Installation.md#recommended-hardware-requirements) and the selected [Deployment Scheme](documentation/Installation.md#deployment-schemes). Make sure the nodes meet [Cluster Nodes Prerequisites](documentation/Installation.md#prerequisites-for-cluster-nodes).
1. Create the `cluster.yaml` inventory file, and describe your environment. Make sure that all configurations are done. For more information, see [inventory configs available](documentation/Installation.md#configuration) and [examples](examples/cluster.yaml). No need to enter all the parameters that are available, it is enough to specify the minimal identification data about the nodes where you want to install the cluster, for example:
   ```yaml
   node_defaults:
     keyfile: "/home/username/.ssh/id_rsa"
     username: "centos"

   vrrp_ips:
     - 192.168.0.250

   nodes:
     - name: "k8s-control-plane-1"
       address: "10.101.0.1"
       internal_address: "192.168.0.1"
       roles: ["balancer", "control-plane", "worker"]
     - name: "k8s-control-plane-2"
       address: "10.101.0.2"
       internal_address: "192.168.0.2"
       roles: ["balancer", "control-plane", "worker"]
     - name: "k8s-control-plane-3"
       address: "10.101.0.3"
       internal_address: "192.168.0.3"
       roles: ["balancer", "control-plane", "worker"]

   cluster_name: "k8s.example.com"
   ```
1. Move `cluster.yaml` to the directory where Kubemarine is installed.
1. Verify the infrastructure:
   ```bash
   kubemarine check_iaas
   ```
1. Start the installation:
   ```bash
   kubemarine install
   ```
1. Check the health of the newly installed cluster:
   ```bash
   kubemarine check_paas
   ```

For more information, refer to the other [Kubemarine guides](#documentation).

## Kubemarine Docker Installation
To start, download the Kubmarine image ```docker pull ghcr.io/netcracker/kubemarine:main```

Run Kubemarine from the container, for example:
   ```
   docker run -it --mount type=bind,source=/root/cluster.yaml,target=/opt/kubemarine/cluster.yaml --mount type=bind,source=/root/rsa_key,target=/opt/kubemarine/rsa_key kubemarine install -c /opt/kubemarine/cluster.yaml
   ```
   *Note*: Do not forget to pass the inventory file and connection key inside the container.
   For more execution details, refer to ["Installation of Kubernetes using CLI" guide on Github](https://github.com/Netcracker/kubemarine/blob/main/documentation/Installation.md#installation-of-kubernetes-using-cli).

## Documentation
The following documents and tutorials are available:
- [Installation](documentation/Installation.md)
- [Maintenance](documentation/Maintenance.md)
- [Troubleshooting](documentation/Troubleshooting.md)
- [Kubecheck](documentation/Kubecheck.md)
- [Logging](documentation/Logging.md)

Also, check out the following inventory examples:
- [cluster.yaml](examples/cluster.yaml)
- [procedure.yaml](examples/procedure.yaml)

## Issues, Questions
If you have any problems while working with Kubemarine, feel free to open a [new issue](https://github.com/netcracker/kubemarine/issues) or even
[PR](https://github.com/netcracker/kubemarine/pulls) with related changes.
Please follow the [Contribution Guide](CONTRIBUTING.md ) and the process outlined in the Stack Overflow [MCVE](https://stackoverflow.com/help/mcve) document.

In case of security concerns, please follow the [Security Reporting Process](SECURITY.md)
## Changelog
Detailed changes for each release are documented in the [release notes](https://github.com/netcracker/kubemarine/releases).

## License
[Apache License 2.0](LICENSE)
