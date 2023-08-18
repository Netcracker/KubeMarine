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
from typing import Optional, List, Dict

import os

from kubemarine.core import utils, log
from kubemarine.core.cluster import KubernetesCluster
from kubemarine.plugins.manifest import Processor, EnrichmentFunction, Manifest


def enrich_inventory(inventory: dict, cluster: KubernetesCluster) -> dict:
    if not inventory["plugins"]["calico"]["install"]:
        return inventory

    # if user defined resources himself, we should use them as is, instead of merging with our defaults
    raw_calico_node = cluster.raw_inventory.get("plugins", {}).get("calico", {}).get("node", {})
    if "resources" in raw_calico_node:
        inventory["plugins"]["calico"]["node"]["resources"] = raw_calico_node["resources"]
    raw_typha = cluster.raw_inventory.get("plugins", {}).get("calico", {}).get("typha", {})
    if "resources" in raw_typha:
        inventory["plugins"]["calico"]["typha"]["resources"] = raw_typha["resources"]
    raw_calico_controller = cluster.raw_inventory.get("plugins", {}).get("calico", {}).get("kube-controllers", {})
    if "resources" in raw_calico_controller:
        inventory["plugins"]["calico"]["kube-controllers"]["resources"] = raw_calico_controller["resources"]

    return inventory


# DEPRECATED
def apply_calico_yaml(cluster: KubernetesCluster, calico_original_yaml: str, calico_yaml: str) -> None:
    """
    The method implements full processing for Calico plugin
    :param calico_original_yaml: path to original Calico manifest
    :param calico_yaml: file name of the resulting Calico manifest
    :param cluster: Cluster object
    """

    calico_yaml = os.path.basename(calico_yaml)
    processor = CalicoManifestProcessor(cluster.log, cluster.inventory,
                                        original_yaml_path=calico_original_yaml,
                                        destination_name=calico_yaml)
    manifest = processor.enrich()
    processor.apply(cluster, manifest)


class CalicoManifestProcessor(Processor):
    def __init__(self, logger: log.VerboseLogger, inventory: dict,
                 original_yaml_path: Optional[str] = None, destination_name: Optional[str] = None):
        super().__init__(logger, inventory, 'calico', original_yaml_path, destination_name)

    def exclude_typha_objects_if_disabled(self, manifest: Manifest) -> None:
        # enrich 'calico-typha' objects only if it's enabled in 'cluster.yaml'
        # in other case those objects must be excluded
        str_value = utils.true_or_false(self.inventory['plugins']['calico']['typha']['enabled'])
        if str_value == 'false':
            for key in ("Deployment_calico-typha", "Service_calico-typha", "PodDisruptionBudget_calico-typha"):
                self.exclude(manifest, key)
        elif str_value == 'true':
            return
        else:
            raise Exception(f"plugins.calico.typha.enabled must be set in 'True' or 'False' "
                            f"as string or boolean value")

    def enrich_configmap_calico_config(self, manifest: Manifest) -> None:
        """
        The method implements the enrichment procedure for Calico ConfigMap
        :param manifest: Container to operate with manifest objects
        """

        key = "ConfigMap_calico-config"
        source_yaml = manifest.get_obj(key, patch=True)
        val = self.inventory['plugins']['calico']['mtu']
        source_yaml['data']['veth_mtu'] = str(val)
        self.log.verbose(f"The {key} has been patched in 'data.veth_mtu' with '{val}'")
        str_value = utils.true_or_false(self.inventory['plugins']['calico']['typha']['enabled'])
        if str_value == "true":
            val = "calico-typha"
        elif str_value == "false":
            val = "none"
        source_yaml['data']['typha_service_name'] = val
        self.log.verbose(f"The {key} has been patched in 'data.typha_service_name' with '{val}'")
        string_part = source_yaml['data']['cni_network_config']
        ip = self.inventory['services']['kubeadm']['networking']['podSubnet'].split('/')[0]
        if type(ipaddress.ip_address(ip)) is ipaddress.IPv4Address:
            val = self.inventory['plugins']['calico']['cni']['ipam']['ipv4']
        else:
            val = self.inventory['plugins']['calico']['cni']['ipam']['ipv6']
        new_string_part = string_part.replace('"type": "calico-ipam"', str(val)[:-1][1:].replace("'", "\""))
        source_yaml['data']['cni_network_config'] = new_string_part
        log_str = new_string_part.replace("\n", "")
        self.log.verbose(f"The {key} has been patched in 'data.cni_network_config' with '{log_str}'")

    def enrich_deployment_calico_kube_controllers(self, manifest: Manifest) -> None:
        """
        The method implements the enrichment procedure for Calico controller Deployment
        :param manifest: Container to operate with manifest objects
        """

        key = "Deployment_calico-kube-controllers"
        self.enrich_node_selector(manifest, key, plugin_service='kube-controllers')
        self.enrich_resources_for_container(manifest, key,
            plugin_service='kube-controllers', container_name='calico-kube-controllers')
        self.enrich_image_for_container(manifest, key,
            plugin_service='kube-controllers', container_name='calico-kube-controllers', is_init_container=False)

    def enrich_daemonset_calico_node(self, manifest: Manifest) -> None:
        """
        The method implements the enrichment procedure for Calico node DaemonSet
        :param manifest: Container to operate with manifest objects
        """

        key = "DaemonSet_calico-node"
        for container_name in ['upgrade-ipam', 'install-cni']:
            self.enrich_image_for_container(manifest, key,
                plugin_service='cni', container_name=container_name, is_init_container=True)

        self.enrich_image_for_container(manifest, key,
            plugin_service='node', container_name='mount-bpffs', is_init_container=True, allow_absent=True)
        self.enrich_image_for_container(manifest, key,
            plugin_service='flexvol', container_name='flexvol-driver', is_init_container=True, allow_absent=True)

        self.enrich_image_for_container(manifest, key,
            plugin_service='node', container_name='calico-node', is_init_container=False)

        container_pos, container = self.find_container_for_patch(manifest, key,
            container_name='calico-node', is_init_container=False)

        self.enrich_daemonset_calico_node_container_env(container_pos, container)
        self.enrich_resources_for_container(manifest, key,
            plugin_service='node', container_name='calico-node')

    def enrich_daemonset_calico_node_container_env(self, container_pos: int, container: dict) -> None:
        """
        The method implements the enrichment procedure for 'calico-node' container in Calico node DaemonSet.
        The method attempts to preserve initial formatting.

        :param container_pos: container position in spec
        :param container: object describing a container
        """
        key = "DaemonSet_calico-node"
        env_delete: List[str] = []
        ip = self.inventory['services']['kubeadm']['networking']['podSubnet'].split('/')[0]
        if type(ipaddress.ip_address(ip)) is ipaddress.IPv4Address:
            env_delete.extend([
                'CALICO_IPV6POOL_CIDR', 'IP6', 'IP6_AUTODETECTION_METHOD',
                'CALICO_IPV6POOL_IPIP', 'CALICO_IPV6POOL_VXLAN'
            ])
        if utils.true_or_false(self.inventory['plugins']['calico']['typha']['enabled']) == "false":
            env_delete.append('FELIX_TYPHAK8SSERVICENAME')

        for name in env_delete:
            for i, e in enumerate(container['env']):
                if e['name'] == name:
                    del container['env'][i]
                    self.log.verbose(f"The {name!r} env variable has been removed from "
                                    f"'spec.template.spec.containers.[{container_pos}].env' in the {key}")
                    break

        env_update: Dict[str, dict] = {}
        for name, value in self.inventory['plugins']['calico']['env'].items():
            if name in env_delete:
                continue
            if type(value) is str:
                env_update[name] = {'value': value}
            elif type(value) is dict:
                env_update[name] = {'valueFrom': value}
            self.log.verbose(f"The {key} has been patched in "
                            f"'spec.template.spec.containers.[{container_pos}].env.{name}' with '{value}'")

        for env in container['env']:
            name = env['name']
            if name not in env_update:
                continue

            value = env_update.pop(name)
            keys = list(env.keys())
            for key in keys:
                if key != 'name' and key not in value:
                    del env[key]

            env.update(value)

        for name, env in env_update.items():
            new_env = {'name' : name}
            new_env.update(env)
            container['env'].append(new_env)

    def enrich_deployment_calico_typha(self, manifest: Manifest) -> None:
        """
        The method implements the enrichment procedure for Typha Deployment
        :param manifest: Container to operate with manifest objects
        """

        key = "Deployment_calico-typha"
        if not manifest.has_obj(key):
            return None
        source_yaml = manifest.get_obj(key, patch=True)

        default_tolerations = [{'key': 'node.kubernetes.io/network-unavailable', 'effect': 'NoSchedule'},
                               {'key': 'node.kubernetes.io/network-unavailable', 'effect': 'NoExecute'}]

        val = self.inventory['plugins']['calico']['typha']['replicas']
        source_yaml['spec']['replicas'] = int(val)
        self.log.verbose(f"The {key} has been patched in 'spec.replicas' with '{val}'")

        self.enrich_node_selector(manifest, key, plugin_service='typha')
        self.enrich_tolerations(manifest, key, plugin_service='typha', extra_tolerations=default_tolerations)
        self.enrich_image_for_container(manifest, key,
            plugin_service='typha', container_name='calico-typha', is_init_container=False)
        self.enrich_resources_for_container(manifest, key,
            plugin_service='typha', container_name='calico-typha')


    def enrich_clusterrole_calico_kube_controllers(self, manifest: Manifest) -> None:
        """
        The method implements the enrichment procedure for Calico controller ClusterRole
        :param manifest: Container to operate with manifest objects
        """

        key = "ClusterRole_calico-kube-controllers"
        if self.inventory['rbac']['admission'] == "psp" and \
                self.inventory['rbac']['psp']['pod-security'] == "enabled":
            source_yaml = manifest.get_obj(key, patch=True)
            api_list = source_yaml['rules']
            api_list.append(psp_calico_kube_controllers)
            self.log.verbose(f"The {key} has been patched in 'rules' with '{psp_calico_kube_controllers}'")

    def enrich_clusterrole_calico_node(self, manifest: Manifest) -> None:
        """
        The method implements the enrichment procedure for Calico node ClusterRole
        :param manifest: Container to operate with manifest objects
        """

        key = "ClusterRole_calico-node"
        if self.inventory['rbac']['admission'] == "psp" and \
                self.inventory['rbac']['psp']['pod-security'] == "enabled":
            source_yaml = manifest.get_obj(key, patch=True)
            api_list = source_yaml['rules']
            api_list.append(psp_calico_node)
            self.log.verbose(f"The {key} has been patched in 'rules' with '{psp_calico_node}'")

    def enrich_crd_felix_configuration(self, manifest: Manifest) -> None:
        """
        The method implements the enrichment procedure for Calico CRD Felixconfigurations
        :param manifest: Container to operate with manifest objects
        """

        key = "CustomResourceDefinition_felixconfigurations.crd.projectcalico.org"
        source_yaml = manifest.get_obj(key, patch=True)

        api_list = \
        source_yaml['spec']['versions'][0]['schema']['openAPIV3Schema']['properties']['spec']['properties'][
            'prometheusMetricsEnabled']
        api_list["default"] = True
        source_yaml['spec']['versions'][0]['schema']['openAPIV3Schema']['properties']['spec']['properties'][
            'prometheusMetricsEnabled'] = api_list

        sz = len(manifest.all_obj_keys())
        import ruamel.yaml
        self.include(manifest, sz, ruamel.yaml.safe_load(utils.read_internal('templates/plugins/calico-kube-controllers-metrics.yaml')))
        self.include(manifest, sz, ruamel.yaml.safe_load(utils.read_internal('templates/plugins/calico-metrics.yaml')))

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
            self.exclude_typha_objects_if_disabled,
            self.enrich_configmap_calico_config,
            self.enrich_deployment_calico_kube_controllers,
            self.enrich_daemonset_calico_node,
            self.enrich_deployment_calico_typha,
            self.enrich_clusterrole_calico_kube_controllers,
            self.enrich_clusterrole_calico_node,
            self.enrich_crd_felix_configuration,
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
