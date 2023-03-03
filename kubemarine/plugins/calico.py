# Copyright 2021-2022 NetCracker Technology Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import ipaddress
from typing import Optional, List

import os

from kubemarine.core import utils
from kubemarine.core.cluster import KubernetesCluster
from kubemarine.plugins.manifest import EnrichmentFunction, Manifest, Processor


def enrich_inventory(inventory, cluster):

    # By default, we use calico, but have to find it out
    # First of all we have to check is Calicon set to be installed or not
    # By default installation parameter is unset, means user did not make any decision
    if inventory["plugins"]["calico"].get("install") is None:
        # Is user defined Flannel plugin and set it to install?
        flannel_required = inventory["plugins"].get("flannel", {}).get("install", False)
        # Is user defined Canal plugin and set it to install?
        canal_required = inventory["plugins"].get("canal", {}).get("install", False)
        # If Flannel and Canal is unset or not required to install, then install Calico
        if not flannel_required and not canal_required:
            inventory["plugins"]["calico"]["install"] = True

    return inventory


# DEPRECATED
def apply_calico_yaml(cluster: KubernetesCluster, calico_original_yaml: str, calico_yaml: str):
    """
    The method implements full processing for Calico plugin
    :param calico_original_yaml: path to original Calico manifest
    :param calico_yaml: file name of the resulting Calico manifest
    :param cluster: Cluster object
    """

    calico_yaml = os.path.basename(calico_yaml)
    processor = CalicoManifestProcessor(cluster, cluster.inventory,
                                        original_yaml_path=calico_original_yaml,
                                        destination_name=calico_yaml)
    processor.apply()


def exclude_typha_objects_if_disabled(cluster: KubernetesCluster, manifest: Manifest) -> None:
    # enrich 'calico-typha' objects only if it's enabled in 'cluster.yaml'
    # in other case those objects must be excluded
    str_value = utils.true_or_false(cluster.inventory['plugins']['calico']['typha']['enabled'])
    if str_value == 'false':
        for key in ("Deployment_calico-typha", "Service_calico-typha", "PodDisruptionBudget_calico-typha"):
            manifest.exclude(key)
    elif str_value == 'true':
        return
    else:
        raise Exception(f"plugins.calico.typha.enabled must be set in 'True' or 'False' "
                        f"as string or boolean value")


def enrich_configmap_calico_config(cluster: KubernetesCluster, manifest: Manifest) -> None:
    """
    The method implements the enrichment procedure for Calico ConfigMap
    :param cluster: Cluster object
    :param manifest: Container to operate with manifest objects
    """

    key = "ConfigMap_calico-config"
    source_yaml = manifest.get_obj(key, patch=True)
    val = cluster.inventory['plugins']['calico']['mtu']
    source_yaml['data']['veth_mtu'] = str(val)
    cluster.log.verbose(f"The {key} has been patched in 'data.veth_mtu' with '{val}'")
    str_value = utils.true_or_false(cluster.inventory['plugins']['calico']['typha']['enabled'])
    if str_value == "true":
        val = "calico-typha"
    elif str_value == "false":
        val = "none"
    source_yaml['data']['typha_service_name'] = val
    cluster.log.verbose(f"The {key} has been patched in 'data.typha_service_name' with '{val}'")
    string_part = source_yaml['data']['cni_network_config']
    ip = cluster.inventory['services']['kubeadm']['networking']['podSubnet'].split('/')[0]
    if type(ipaddress.ip_address(ip)) is ipaddress.IPv4Address:
        val = cluster.inventory['plugins']['calico']['cni']['ipam']['ipv4']
    else:
        val = cluster.inventory['plugins']['calico']['cni']['ipam']['ipv6']
    new_string_part = string_part.replace('"type": "calico-ipam"', str(val)[:-1][1:].replace("'", "\""))
    source_yaml['data']['cni_network_config'] = new_string_part
    log_str = new_string_part.replace("\n", "")
    cluster.log.verbose(f"The {key} has been patched in 'data.cni_network_config' with '{log_str}'")


def enrich_deployment_calico_kube_controllers(cluster: KubernetesCluster, manifest: Manifest) -> None:
    """
    The method implements the enrichment procedure for Calico controller Deployment
    :param cluster: Cluster object
    :param manifest: Container to operate with manifest objects
    """

    key = "Deployment_calico-kube-controllers"
    source_yaml = manifest.get_obj(key, patch=True)
    source_yaml['spec']['template']['spec']['nodeSelector'] = \
            cluster.inventory['plugins']['calico']['kube-controllers']['nodeSelector']
    for container in source_yaml['spec']['template']['spec']['containers']:
        if container['name'] == "calico-kube-controllers":
            num = source_yaml['spec']['template']['spec']['containers'].index(container)
            val = enrich_image(cluster, cluster.inventory['plugins']['calico']['kube-controllers']['image'])
            source_yaml['spec']['template']['spec']['containers'][num]['image'] = val
            cluster.log.verbose(f"The {key} has been patched in "
                                f"'spec.template.spec.containers.[{num}].image with '{val}'")


def enrich_daemonset_calico_node(cluster: KubernetesCluster, manifest: Manifest) -> None:
    """
    The method implements the enrichment procedure for Calico node DaemonSet
    :param cluster: Cluster object
    :param manifest: Container to operate with manifest objects
    """

    key = "DaemonSet_calico-node"
    source_yaml = manifest.get_obj(key, patch=True)
    for container in source_yaml['spec']['template']['spec']['initContainers']:
        if container['name'] in ['upgrade-ipam', 'install-cni']: 
            num = source_yaml['spec']['template']['spec']['initContainers'].index(container)
            val = enrich_image(cluster, cluster.inventory['plugins']['calico']['cni']['image'])
            source_yaml['spec']['template']['spec']['initContainers'][num]['image'] = val
            cluster.log.verbose(f"The {key} has been patched in "
                                f"'spec.template.spec.initContainers.[{num}].image' with '{val}'")
        if container['name'] == "mount-bpffs":
            num = source_yaml['spec']['template']['spec']['initContainers'].index(container)
            val = enrich_image(cluster, cluster.inventory['plugins']['calico']['node']['image'])
            source_yaml['spec']['template']['spec']['initContainers'][num]['image'] = val
            cluster.log.verbose(f"The {key} has been patched in "
                                f"'spec.template.spec.initContainers.[{num}].image' with '{val}'")
        if container['name'] == "flexvol-driver":
            num = source_yaml['spec']['template']['spec']['initContainers'].index(container)
            val = enrich_image(cluster, cluster.inventory['plugins']['calico']['flexvol']['image'])
            source_yaml['spec']['template']['spec']['initContainers'][num]['image'] = val
            cluster.log.verbose(f"The {key} has been patched in "
                                f"'spec.template.spec.initContainers.[{num}].image' with '{val}'")
    for container in source_yaml['spec']['template']['spec']['containers']:
        if container['name'] == "calico-node":
            num = source_yaml['spec']['template']['spec']['containers'].index(container)
            val = enrich_image(cluster, cluster.inventory['plugins']['calico']['node']['image'])
            source_yaml['spec']['template']['spec']['containers'][num]['image'] = val
            cluster.log.verbose(f"The {key} has been patched in "
                                f"'spec.template.spec.containers.[{num}].image' with '{val}'")
            ipv6_env = ['CALICO_IPV6POOL_CIDR', 'IP6', 'IP6_AUTODETECTION_METHOD', 'FELIX_IPV6SUPPORT', 
                        'CALICO_IPV6POOL_IPIP', 'CALICO_IPV6POOL_VXLAN']
            env_list = []
            for name, value in cluster.inventory['plugins']['calico']['env'].items():
                ip = cluster.inventory['services']['kubeadm']['networking']['podSubnet'].split('/')[0]
                if name not in ipv6_env and name != 'FELIX_TYPHAK8SSERVICENAME':
                    if type(value) is str:
                        env_list.append({'name': name, 'value': value})
                    elif type(value) is dict:
                        env_list.append({'name': name, 'valueFrom': value})
                    cluster.log.verbose(f"The {key} has been patched in "
                                        f"'spec.template.spec.containers.[{num}].env.{name}' with '{value}'")
                elif name in ipv6_env and type(ipaddress.ip_address(ip)) is not ipaddress.IPv4Address:
                    if type(value) is str:
                        env_list.append({'name': name, 'value': value})
                    elif type(value) is dict:
                        env_list.append({'name': name, 'valueFrom': value})
                    cluster.log.verbose(f"The {key} has been patched in "
                                        f"'spec.template.spec.containers.[{num}].env.{name}' with '{value}'")
                if utils.true_or_false(cluster.inventory['plugins']['calico']['typha']['enabled']) == "true" and \
                        name == 'FELIX_TYPHAK8SSERVICENAME':
                    env_list.append({'name': name, 'valueFrom': value})
                    cluster.log.verbose(f"The {key} has been patched in "
                                        f"'spec.template.spec.containers.[{num}].env.{name}' with '{value}'")
            i = 0
            for env in source_yaml['spec']['template']['spec']['containers'][num]['env']:
                for item in env_list:
                    if env['name'] == item['name']:
                        source_yaml['spec']['template']['spec']['containers'][num]['env'][i] = item
                i += 1


def enrich_deployment_calico_typha(cluster: KubernetesCluster, manifest: Manifest) -> None:
    """
    The method implements the enrichment procedure for Typha Deployment
    :param cluster: Cluster object
    :param manifest: Container to operate with manifest objects
    """

    key = "Deployment_calico-typha"
    source_yaml = manifest.get_obj(key, patch=True, allow_absent=True)
    if source_yaml is None:
        return

    default_tolerations = [{'key': 'node.kubernetes.io/network-unavailable', 'effect': 'NoSchedule'},
                           {'key': 'node.kubernetes.io/network-unavailable', 'effect': 'NoExecute'}]

    val = cluster.inventory['plugins']['calico']['typha']['replicas']
    source_yaml['spec']['replicas'] = int(val)
    cluster.log.verbose(f"The {key} has been patched in 'spec.replicas' with '{val}'")
    val = cluster.inventory['plugins']['calico']['typha']['nodeSelector']
    source_yaml['spec']['template']['spec']['nodeSelector'] = val
    cluster.log.verbose(f"The {key} has been patched in 'spec.template.spec.nodeSelector' with '{val}'")
    for val in default_tolerations:
        source_yaml['spec']['template']['spec']['tolerations'].append(val)
        cluster.log.verbose(f"The {key} has been patched in 'spec.template.spec.tolerations' with '{val}'")
    for val in cluster.inventory['plugins']['calico']['typha'].get('tolerations', ''):
        source_yaml['spec']['template']['spec']['tolerations'].append(val)
        cluster.log.verbose(f"The {key} has been patched in 'spec.template.spec.tolerations' with '{val}'")
    for container in source_yaml['spec']['template']['spec']['containers']:
        if container['name'] == "calico-typha":
            num = source_yaml['spec']['template']['spec']['containers'].index(container)
            val = enrich_image(cluster, cluster.inventory['plugins']['calico']['typha']['image'])
            source_yaml['spec']['template']['spec']['containers'][num]['image'] = val
            cluster.log.verbose(f"The {key} has been patched in "
                                f"'spec.template.spec.containers.[{num}].image with '{val}'")


def enrich_clusterrole_calico_kube_controllers(cluster: KubernetesCluster, manifest: Manifest) -> None:
    """
    The method implements the enrichment procedure for Calico controller ClusterRole
    :param cluster: Cluster object
    :param manifest: Container to operate with manifest objects
    """

    key = "ClusterRole_calico-kube-controllers"
    source_yaml = manifest.get_obj(key, patch=True)
    if cluster.inventory['rbac']['admission'] == "psp" and \
            cluster.inventory['rbac']['psp']['pod-security'] == "enabled":
        api_list = source_yaml['rules']
        api_list.append(psp_calico_kube_controllers)
        source_yaml['rules'] = api_list
        cluster.log.verbose(f"The {key} has been patched in 'rules' with '{psp_calico_kube_controllers}'")


def enrich_clusterrole_calico_node(cluster: KubernetesCluster, manifest: Manifest) -> None:
    """
    The method implements the enrichment procedure for Calico node ClusterRole
    :param cluster: Cluster object
    :param manifest: Container to operate with manifest objects
    """

    key = "ClusterRole_calico-node"
    source_yaml = manifest.get_obj(key, patch=True)
    if cluster.inventory['rbac']['admission'] == "psp" and \
            cluster.inventory['rbac']['psp']['pod-security'] == "enabled":
        api_list = source_yaml['rules']
        api_list.append(psp_calico_node)
        source_yaml['rules'] = api_list
        cluster.log.verbose(f"The {key} has been patched in 'rules' with '{psp_calico_node}'")


def enrich_image(cluster, image):
    """
    The method adds registry to image if it's necessary
    :param cluster: Cluster object
    :param image: particular image
    """
    if cluster.inventory['plugins']['calico']['installation'].get('registry', ''):
        if len(cluster.inventory['plugins']['calico']['installation']['registry']):
            return f"{cluster.inventory['plugins']['calico']['installation']['registry']}/{image}"

    return image


class CalicoManifestProcessor(Processor):
    def __init__(self, cluster: KubernetesCluster, inventory: dict,
                 plugin_name='calico',
                 original_yaml_path: Optional[str] = None, destination_name: Optional[str] = None):
        version = inventory['plugins'][plugin_name]['version']
        if original_yaml_path is None:
            original_yaml_path = f"plugins/yaml/calico-{version}.yaml.original"
        if destination_name is None:
            destination_name = f"calico-{version}.yaml"
        super().__init__(cluster, inventory, plugin_name, original_yaml_path, destination_name)

    def get_known_objects(self) -> List[str]:
        return [
            "ConfigMap_calico-config",
            "CustomResourceDefinition_bgpconfigurations.crd.projectcalico.org",
            "CustomResourceDefinition_bgppeers.crd.projectcalico.org",
            "CustomResourceDefinition_blockaffinities.crd.projectcalico.org",
            "CustomResourceDefinition_caliconodestatuses.crd.projectcalico.org",
            "CustomResourceDefinition_clusterinformations.crd.projectcalico.org",
            "CustomResourceDefinition_felixconfigurations.crd.projectcalico.org",
            "CustomResourceDefinition_globalnetworkpolicies.crd.projectcalico.org",
            "CustomResourceDefinition_globalnetworksets.crd.projectcalico.org",
            "CustomResourceDefinition_hostendpoints.crd.projectcalico.org",
            "CustomResourceDefinition_ipamblocks.crd.projectcalico.org",
            "CustomResourceDefinition_ipamconfigs.crd.projectcalico.org",
            "CustomResourceDefinition_ipamhandles.crd.projectcalico.org",
            "CustomResourceDefinition_ippools.crd.projectcalico.org",
            "CustomResourceDefinition_ipreservations.crd.projectcalico.org",
            "CustomResourceDefinition_kubecontrollersconfigurations.crd.projectcalico.org",
            "CustomResourceDefinition_networkpolicies.crd.projectcalico.org",
            "CustomResourceDefinition_networksets.crd.projectcalico.org",
            "ClusterRole_calico-kube-controllers",
            "ClusterRoleBinding_calico-kube-controllers",
            "ClusterRole_calico-node",
            "ClusterRoleBinding_calico-node",
            "DaemonSet_calico-node",
            "ServiceAccount_calico-node",
            "Deployment_calico-kube-controllers",
            "ServiceAccount_calico-kube-controllers",
            "PodDisruptionBudget_calico-kube-controllers",
            "Deployment_calico-typha",
            "Service_calico-typha",
            "PodDisruptionBudget_calico-typha"
        ]

    def get_enrichment_functions(self) -> List[EnrichmentFunction]:
        return [
            exclude_typha_objects_if_disabled,
            enrich_configmap_calico_config,
            enrich_deployment_calico_kube_controllers,
            enrich_daemonset_calico_node,
            enrich_deployment_calico_typha,
            enrich_clusterrole_calico_kube_controllers,
            enrich_clusterrole_calico_node,
        ]


psp_calico_kube_controllers = {
        "apiGroups": ["policy"],
        "resources": ["podsecuritypolicies"],
        "verbs":     ["use"],
        "resourceNames": ["oob-anyuid-psp"]
}

psp_calico_node = {
        "apiGroups": ["policy"],
        "resources": ["podsecuritypolicies"],
        "verbs":     ["use"],
        "resourceNames": ["oob-privileged-psp"]
}
