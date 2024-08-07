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
from textwrap import dedent
from typing import Optional, List, Dict

import os
import yaml

from kubemarine import plugins
from kubemarine.core import utils, log
from kubemarine.core.cluster import KubernetesCluster, EnrichmentStage, enrichment
from kubemarine.core.group import NodeGroup
from kubemarine.kubernetes import secrets
from kubemarine.plugins.manifest import Processor, EnrichmentFunction, Manifest, Identity


@enrichment(EnrichmentStage.FULL)
def enrich_inventory(cluster: KubernetesCluster) -> None:
    inventory = cluster.inventory
    if not inventory["plugins"]["calico"]["install"]:
        return

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
    raw_apiserver = cluster.raw_inventory.get("plugins", {}).get("calico", {}).get("apiserver", {})
    if "resources" in raw_apiserver:
        inventory["plugins"]["calico"]["apiserver"]["resources"] = raw_apiserver["resources"]


@enrichment(EnrichmentStage.PROCEDURE, procedures=['remove_node'])
def enrich_remove_node_set_previous_typha_enabled(cluster: KubernetesCluster) -> None:
    if not cluster.previous_inventory["plugins"]["calico"]["install"]:
        return

    # If Typha was (effectively) enabled before removing of node and `enabled` value is not explicitly provided,
    # Let's set previous flag in all inventories including final, as we are not able to fully remove Typha.
    typha_enabled_before = is_typha_enabled(cluster.previous_inventory)
    if typha_enabled_before and 'enabled' not in cluster.inventory.get('plugins', {}).get('calico', {}).get('typha', {}):
        cluster.inventory.setdefault('plugins', {}).setdefault('calico', {})\
            .setdefault('typha', {})['enabled'] = typha_enabled_before


def new_route_reflectors_added(cluster: KubernetesCluster) -> bool:
    procedure = cluster.context['initial_procedure']
    if procedure != 'add_node':
        return False

    calico = cluster.inventory['plugins']['calico']
    if calico['fullmesh']:
        return False

    for node in cluster.get_new_nodes().having_roles(['control-plane', 'worker']).get_ordered_members_configs_list():
        if node.get('labels', {}).get('route-reflector') is True:
            break
    else:
        return False

    steps = calico['installation']['procedures']
    for step in steps:
        if 'template' not in step:
            continue

        if step['template']['source'] == 'templates/plugins/calico-rr.sh.j2':
            break
    else:
        return False

    return True


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


def is_typha_enabled(inventory: dict) -> bool:
    enabled: bool = inventory['plugins']['calico']['typha']['enabled']
    return enabled


def is_apiserver_enabled(inventory: dict) -> bool:
    enabled: bool = inventory['plugins']['calico']['apiserver']['enabled']
    return enabled


def renew_apiserver_certificate(cluster: KubernetesCluster) -> None:
    from kubemarine import kubernetes  # pylint: disable=cyclic-import

    logger = cluster.log
    if not is_apiserver_enabled(cluster.inventory):
        logger.debug("Calico API server is disabled. Skip renewing of the key and certificate.")
        return

    namespace = "calico-apiserver"
    secret_name = "calico-apiserver-certs"
    deployment = "calico-apiserver"

    control_planes = cluster.nodes["control-plane"]
    first_control_plane = control_planes.get_first_member()

    with secrets.create_tls_secret_procedure(first_control_plane):
        logger.debug("Creating or renewing of the key and certificate for the Calico API server")

        config = dedent(
            """\
            [req]
            distinguished_name = req
            [v3_req]
            basicConstraints = critical,CA:TRUE
            subjectAltName = DNS:calico-api.calico-apiserver.svc
            """
        )
        first_control_plane.call(
            secrets.create_certificate,
            config=config,
            customization_flags='-newkey rsa:4096 -days 365 -subj "/" -extensions v3_req')

        first_control_plane.call(secrets.renew_tls_secret, name=secret_name, namespace=namespace)

        logger.debug("Patching the APIService for the Calico API server")

        first_control_plane.sudo(
            f"{secrets.get_encoded_certificate_cmd()} "
            "| xargs -I CERT "
            "sudo kubectl patch apiservice v3.projectcalico.org "
            r'-p "{\"spec\": {\"caBundle\": \"CERT\"}}"')

    # Force restart the deployment instead of graceful waiting for the automatic secret propagation.
    # This is necessary to make the procedure independent on the secret propagation timeout.
    logger.debug("Restarting the Calico API server deployment")
    first_control_plane.sudo(f"kubectl rollout restart -n {namespace} deployment {deployment}")
    plugins.expect_deployment(cluster, [{'name': deployment, 'namespace': namespace}])
    plugins.expect_pods(cluster, ['calico-apiserver'], namespace=namespace)

    logger.debug("Waiting for the Calico API service availability through the Kubernetes API server")

    # Try to access some projectcalico.org resource using each instance of the Kubernetes API server.
    expect_config = cluster.inventory['plugins']['calico']['apiserver']['expect']['apiservice']
    with kubernetes.local_admin_config(control_planes) as kubeconfig:
        control_planes.call(NodeGroup.wait_command_successful,
                            command=f"kubectl --kubeconfig {kubeconfig} get ippools.projectcalico.org > /dev/null",
                            hide=True, pty=True,
                            retries=expect_config['retries'], timeout=expect_config['timeout'])


class CalicoManifestProcessor(Processor):
    def __init__(self, logger: log.VerboseLogger, inventory: dict,
                 original_yaml_path: Optional[str] = None, destination_name: Optional[str] = None):
        super().__init__(logger, inventory, Identity('calico'), original_yaml_path, destination_name)

    def exclude_typha_objects_if_disabled(self, manifest: Manifest) -> None:
        # enrich 'calico-typha' objects only if it's enabled in 'cluster.yaml'
        # in other case those objects must be excluded
        if not is_typha_enabled(self.inventory):
            for key in ("Deployment_calico-typha", "Service_calico-typha", "PodDisruptionBudget_calico-typha"):
                self.exclude(manifest, key)

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
        val = "calico-typha" if is_typha_enabled(self.inventory) else "none"
        source_yaml['data']['typha_service_name'] = val
        self.log.verbose(f"The {key} has been patched in 'data.typha_service_name' with '{val}'")
        string_part = source_yaml['data']['cni_network_config']
        ip = self.inventory['services']['kubeadm']['networking']['podSubnet'].split('/')[0]
        if utils.isipv(ip, [4]):
            val = self.inventory['plugins']['calico']['cni']['ipam']['ipv4']
        else:
            val = self.inventory['plugins']['calico']['cni']['ipam']['ipv6']
        new_string_part = string_part.replace('"type": "calico-ipam"', str(val)[:-1][1:].replace("'", "\""))
        source_yaml['data']['cni_network_config'] = new_string_part
        log_str = new_string_part.replace("\n", "")
        self.log.verbose(f"The {key} has been patched in 'data.cni_network_config' with '{log_str}'")

    def enrich_service_account_secret_calico_kube_controllers(self, manifest: Manifest) -> None:
        new_yaml = yaml.safe_load(service_account_secret_calico_kube_controllers)

        service_account_key = "ServiceAccount_calico-kube-controllers"
        service_account_index = manifest.all_obj_keys().index(service_account_key) \
            if service_account_key in manifest.all_obj_keys() else -1
        
        self.include(manifest, service_account_index + 1, new_yaml)

    def enrich_service_account_calico_kube_controllers(self, manifest: Manifest) -> None:
        key = "ServiceAccount_calico-kube-controllers"
        source_yaml = manifest.get_obj(key, patch=True)
        source_yaml['automountServiceAccountToken'] = False
    
    def enrich_deployment_calico_kube_controllers(self, manifest: Manifest) -> None:
        """
        The method implements the enrichment procedure for Calico controller Deployment
        :param manifest: Container to operate with manifest objects
        """

        key = "Deployment_calico-kube-controllers"
        service_account_name = "calico-kube-controllers"
        source_yaml= manifest.get_obj(key, patch=True)
        self.enrich_volume_and_volumemount(source_yaml, service_account_name)
        self.enrich_node_selector(manifest, key, plugin_service='kube-controllers')
        self.enrich_tolerations(manifest, key, plugin_service='kube-controllers')
        self.enrich_resources_for_container(manifest, key,
            plugin_service='kube-controllers', container_name='calico-kube-controllers')
        self.enrich_image_for_container(manifest, key,
            plugin_service='kube-controllers', container_name='calico-kube-controllers', is_init_container=False)

    def enrich_service_account_secret_calico_node(self, manifest: Manifest) -> None:
        new_yaml = yaml.safe_load(service_account_secret_calico_node)

        service_account_key = "ServiceAccount_calico-node"
        service_account_index = manifest.all_obj_keys().index(service_account_key) \
            if service_account_key in manifest.all_obj_keys() else -1
        
        self.include(manifest, service_account_index + 1, new_yaml)

    def enrich_service_account_calico_node(self, manifest: Manifest) -> None:
        key = "ServiceAccount_calico-node"
        source_yaml = manifest.get_obj(key, patch=True)
        source_yaml['automountServiceAccountToken'] = False
    
    def enrich_daemonset_calico_node(self, manifest: Manifest) -> None:
        """
        The method implements the enrichment procedure for Calico node DaemonSet
        :param manifest: Container to operate with manifest objects
        """

        key = "DaemonSet_calico-node"

        service_account_name = "calico-node"
        init_container_name = "upgrade-ipam"
        source_yaml= manifest.get_obj(key, patch=True)
        self.enrich_volume_and_volumemount(source_yaml, service_account_name, init_container_name)

        for container_name in ['upgrade-ipam', 'install-cni']:
            self.enrich_image_for_container(manifest, key,
                plugin_service='cni', container_name=container_name, is_init_container=True)

        self.enrich_image_for_container(manifest, key,
            plugin_service='node', container_name='mount-bpffs', is_init_container=True, allow_absent=True)
        self.enrich_image_for_container(manifest, key,
            plugin_service='flexvol', container_name='flexvol-driver', is_init_container=True, allow_absent=True)

        self.enrich_image_for_container(manifest, key,
            plugin_service='node', container_name='calico-node', is_init_container=False)

        self.enrich_daemonset_calico_node_container_env(manifest)
        self.enrich_resources_for_container(manifest, key,
            plugin_service='node', container_name='calico-node')

    def enrich_daemonset_calico_node_container_env(self, manifest: Manifest) -> None:
        """
        The method implements the enrichment procedure for 'calico-node' container in Calico node DaemonSet.
        The method attempts to preserve initial formatting.

        :param manifest: Container to operate with manifest objects
        """
        key = "DaemonSet_calico-node"
        env_delete: List[str] = []
        ip = self.inventory['services']['kubeadm']['networking']['podSubnet'].split('/')[0]
        if utils.isipv(ip, [4]):
            env_delete.extend([
                'CALICO_IPV6POOL_CIDR', 'IP6', 'IP6_AUTODETECTION_METHOD',
                'CALICO_IPV6POOL_IPIP', 'CALICO_IPV6POOL_VXLAN'
            ])
        if not is_typha_enabled(self.inventory):
            env_delete.append('FELIX_TYPHAK8SSERVICENAME')

        env_ensure: Dict[str, str] = {
            # If metrics ports are ever configurable,
            # it makes sense to make it configurable for typha and kube-controllers as well.
            # Metrics services should also be patched.
            'FELIX_PROMETHEUSMETRICSPORT': '9091'
        }

        self.enrich_env_for_container(
            manifest, key, container_name='calico-node', env_delete=env_delete, env_ensure=env_ensure)

    def enrich_deployment_calico_typha(self, manifest: Manifest) -> None:
        """
        The method implements the enrichment procedure for Typha Deployment
        :param manifest: Container to operate with manifest objects
        """

        key = "Deployment_calico-typha"
        if not manifest.has_obj(key):
            return None
        source_yaml = manifest.get_obj(key, patch=True)

        service_account_name = "calico-node"
        self.enrich_volume_and_volumemount(source_yaml, service_account_name)
        self.log.verbose(f"The {key} has been updated to include the new secret volume and mount.")

        default_tolerations = [{'key': 'node.kubernetes.io/network-unavailable', 'effect': 'NoSchedule'},
                               {'key': 'node.kubernetes.io/network-unavailable', 'effect': 'NoExecute'}]

        val = self.inventory['plugins']['calico']['typha']['replicas']
        source_yaml['spec']['replicas'] = val
        self.log.verbose(f"The {key} has been patched in 'spec.replicas' with '{val}'")

        self.enrich_node_selector(manifest, key, plugin_service='typha')
        self.enrich_deployment_calico_typha_tolerations(manifest, default_tolerations)
        self.enrich_image_for_container(manifest, key,
            plugin_service='typha', container_name='calico-typha', is_init_container=False)
        self.enrich_deployment_calico_typha_container_env(manifest)
        self.enrich_resources_for_container(manifest, key,
            plugin_service='typha', container_name='calico-typha')

    def enrich_deployment_calico_typha_tolerations(self, manifest: Manifest, default_tolerations: List[dict]) -> None:
        key = "Deployment_calico-typha"
        self.enrich_tolerations(manifest, key, plugin_service='typha', extra_tolerations=default_tolerations)

    def enrich_deployment_calico_typha_container_env(self, manifest: Manifest) -> None:
        key = "Deployment_calico-typha"
        env_ensure: Dict[str, str] = {
            # If metrics ports are ever configurable, it will need to introduce new `typha.env` section.
            # Also, it makes sense to make it configurable for calico-node and kube-controllers as well.
            # Metrics services should also be patched.
            'TYPHA_PROMETHEUSMETRICSENABLED': 'true',
            'TYPHA_PROMETHEUSMETRICSPORT': '9093'
        }
        # This also searches in calico.typha.env but it is currently not supported by JSON schema.
        self.enrich_env_for_container(
            manifest, key, plugin_service='typha', container_name='calico-typha', env_ensure=env_ensure)

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

    def enrich_metrics(self, manifest: Manifest) -> None:
        sz = len(manifest.all_obj_keys())
        yaml = utils.yaml_structure_preserver()
        self.include(manifest, sz, yaml.load(utils.read_internal('templates/plugins/calico-kube-controllers-metrics.yaml')))
        self.include(manifest, sz, yaml.load(utils.read_internal('templates/plugins/calico-metrics.yaml')))
        if is_typha_enabled(self.inventory):
            self.include(manifest, sz, yaml.load(utils.read_internal('templates/plugins/calico-typha-metrics.yaml')))

    def get_known_objects(self) -> List[str]:
        return [
            "ConfigMap_calico-config",
            "CustomResourceDefinition_bgpconfigurations.crd.projectcalico.org",
            "CustomResourceDefinition_bgpfilters.crd.projectcalico.org",
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
            "ClusterRole_calico-cni-plugin",
            "ClusterRoleBinding_calico-node",
            "ClusterRoleBinding_calico-cni-plugin",
            "DaemonSet_calico-node",
            "ServiceAccount_calico-node",
            "ServiceAccount_calico-cni-plugin",
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
            self.enrich_service_account_secret_calico_kube_controllers,
            self.enrich_service_account_calico_kube_controllers,
            self.enrich_deployment_calico_kube_controllers,
            self.enrich_service_account_secret_calico_node,
            self.enrich_service_account_calico_node,
            self.enrich_daemonset_calico_node,
            self.enrich_deployment_calico_typha,
            self.enrich_crd_felix_configuration,
            self.enrich_metrics,
        ]


class CalicoLess_3_27_ManifestProcessor(CalicoManifestProcessor):
    def enrich_deployment_calico_typha_tolerations(self, manifest: Manifest, default_tolerations: List[dict]) -> None:
        # "backport" issue https://github.com/projectcalico/calico/pull/7979
        # to allow Typha to be scheduled on control-planes
        for toleration in self.get_typha_schedule_control_plane_extra_tolerations(manifest):
            default_tolerations.insert(0, toleration)

        super().enrich_deployment_calico_typha_tolerations(manifest, default_tolerations)

    def get_typha_schedule_control_plane_extra_tolerations(self, manifest: Manifest) -> List[dict]:
        key = "Deployment_calico-typha"
        source_yaml = manifest.get_obj(key, patch=True)

        schedule_control_plane = [{'effect': 'NoExecute', 'operator': 'Exists'},
                                  {'effect': 'NoSchedule', 'operator': 'Exists'}]

        original_tolerations: List[dict] = source_yaml['spec']['template']['spec'].get('tolerations', [])
        return [toleration for toleration in schedule_control_plane
                if toleration not in original_tolerations]


service_account_secret_calico_node = dedent("""\
    apiVersion: v1
    kind: Secret
    metadata:
      name: calico-node-token
      namespace: kube-system
      annotations:
        kubernetes.io/service-account.name: calico-node
    type: kubernetes.io/service-account-token  
""")
service_account_secret_calico_kube_controllers = dedent("""\
    apiVersion: v1
    kind: Secret
    metadata:
      name: calico-kube-controllers-token
      namespace: kube-system
      annotations:
        kubernetes.io/service-account.name: calico-kube-controllers
    type: kubernetes.io/service-account-token  
""")


def get_calico_manifest_processor(logger: log.VerboseLogger, inventory: dict,
                                  yaml_path: Optional[str] = None, destination: Optional[str] = None) -> Processor:
    version: str = inventory['plugins']['calico']['version']
    kwargs = {'original_yaml_path': yaml_path, 'destination_name': destination}
    if utils.version_key(version)[0:2] < utils.minor_version_key("v3.27"):
        return CalicoLess_3_27_ManifestProcessor(logger, inventory, **kwargs)

    return CalicoManifestProcessor(logger, inventory, **kwargs)


class CalicoApiServerManifestProcessor(Processor):
    def __init__(self, logger: log.VerboseLogger, inventory: dict,
                 original_yaml_path: Optional[str] = None, destination_name: Optional[str] = None):
        super().__init__(logger, inventory, Identity('calico', 'apiserver'), original_yaml_path, destination_name)

    def get_known_objects(self) -> List[str]:
        return [
            "Namespace_calico-apiserver",
            "NetworkPolicy_allow-apiserver",
            "Service_calico-api",
            "Deployment_calico-apiserver",
            "ServiceAccount_calico-apiserver",
            "APIService_v3.projectcalico.org",
            "ClusterRole_calico-crds",
            "ClusterRole_calico-extension-apiserver-auth-access",
            "ClusterRole_calico-webhook-reader",
            "ClusterRoleBinding_calico-apiserver-access-crds",
            "ClusterRoleBinding_calico-apiserver-delegate-auth",
            "ClusterRoleBinding_calico-apiserver-webhook-reader",
            "ClusterRoleBinding_calico-extension-apiserver-auth-access",
        ]

    def get_enrichment_functions(self) -> List[EnrichmentFunction]:
        return [
            self.enrich_namespace_calico_apiserver,
            self.enrich_service_account_secret_calico_apiserver,
            self.enrich_service_account_calico_apiserver,
            self.enrich_deployment_calico_apiserver,
        ]

    def get_namespace_to_necessary_pss_profiles(self) -> Dict[str, str]:
        return {'calico-apiserver': 'baseline'}

    def enrich_namespace_calico_apiserver(self, manifest: Manifest) -> None:
        self.assign_default_pss_labels(manifest, 'calico-apiserver')

    def enrich_service_account_secret_calico_apiserver(self, manifest: Manifest) -> None:
        new_yaml = yaml.safe_load(service_account_secret_calico_apiserver)

        service_account_key = "ServiceAccount_calico-apiserver"
        service_account_index = manifest.all_obj_keys().index(service_account_key) \
            if service_account_key in manifest.all_obj_keys() else -1
        
        self.include(manifest, service_account_index + 1, new_yaml)

    def enrich_service_account_calico_apiserver(self, manifest: Manifest) -> None:
        key = "ServiceAccount_calico-apiserver"
        source_yaml = manifest.get_obj(key, patch=True)
        source_yaml['automountServiceAccountToken'] = False

    def enrich_deployment_calico_apiserver(self, manifest: Manifest) -> None:
        key = "Deployment_calico-apiserver"
        source_yaml = manifest.get_obj(key, patch=True)
        service_account_name = "calico-apiserver"
        self.enrich_node_selector(manifest, key, plugin_service='apiserver')
        self.enrich_tolerations(manifest, key, plugin_service='apiserver')
        self.enrich_image_for_container(
            manifest, key, plugin_service='apiserver', container_name='calico-apiserver', is_init_container=False)
        self.enrich_resources_for_container(
            manifest, key, plugin_service='apiserver', container_name='calico-apiserver')
        self.enrich_volume_and_volumemount(source_yaml, service_account_name)

        self.enrich_deployment_calico_apiserver_container(manifest)

    def enrich_deployment_calico_apiserver_container(self, manifest: Manifest) -> None:
        key = "Deployment_calico-apiserver"
        # By default, API server searches in the same directory as specified below,
        # but with different file names: apiserver.crt, apiserver.key
        # There is no real necessity to change paths
        # except to make TLS secret creation process the same as for nginx-ingress.
        additional_args = [
            "--tls-cert-file=apiserver.local.config/certificates/tls.crt",
            "--tls-private-key-file=apiserver.local.config/certificates/tls.key"
        ]
        # This also searches in calico.apiserver.args but it is currently not supported by JSON schema.
        self.enrich_args_for_container(
            manifest, key, plugin_service='apiserver', container_name='calico-apiserver',
            extra_args=additional_args)


service_account_secret_calico_apiserver = dedent("""\
    apiVersion: v1
    kind: Secret
    metadata:
      name: calico-apiserver-token
      namespace: calico-apiserver
      annotations:
        kubernetes.io/service-account.name: calico-apiserver
    type: kubernetes.io/service-account-token  
""")
