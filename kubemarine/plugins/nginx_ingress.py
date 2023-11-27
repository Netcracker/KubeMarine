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

import io
import ipaddress
from typing import Optional, List, Dict

from kubemarine.core import utils, log
from kubemarine.core.cluster import KubernetesCluster
from kubemarine.core.group import NodeGroup
from kubemarine.kubernetes import secrets
from kubemarine.plugins.manifest import Processor, EnrichmentFunction, Manifest, Identity


def check_job_for_nginx(cluster: KubernetesCluster) -> None:
    first_control_plane = cluster.nodes['control-plane'].get_first_member()
    version = cluster.inventory['plugins']['nginx-ingress-controller']['version'].replace('v', '.').split('.')

    major_version = int(version[1])
    minor_version = int(version[2])

    check_jobs = first_control_plane.sudo(f"kubectl get jobs -n ingress-nginx")
    if list(check_jobs.values())[0].stderr == "" and major_version >= 1 and minor_version >= 4:
        cluster.log.debug('Delete old jobs for nginx')
        first_control_plane.sudo(f"sudo kubectl delete job --all -n ingress-nginx")
    else:
        cluster.log.debug('There are no jobs to delete')


def enrich_inventory(inventory: dict, cluster: KubernetesCluster) -> dict:
    if not inventory["plugins"]["nginx-ingress-controller"]["install"]:
        return inventory

    # Change type for hostPorts because of jinja enrichment
    for port in inventory["plugins"]["nginx-ingress-controller"].get("ports", []):
        if "hostPort" in port and not isinstance(port['hostPort'], int):
            port['hostPort'] = int(port['hostPort'])

    if inventory["plugins"]["nginx-ingress-controller"].get('custom_headers'):
        if not inventory["plugins"]["nginx-ingress-controller"].get('config_map'):
            inventory["plugins"]["nginx-ingress-controller"]['config_map'] = {}
        if not inventory["plugins"]["nginx-ingress-controller"]['config_map'].get('proxy-set-headers'):
            inventory["plugins"]["nginx-ingress-controller"]['config_map']['proxy-set-headers'] = 'ingress-nginx/custom-headers'

    # if user defined resources himself, we should use them as is, instead of merging with our defaults
    raw_controller = cluster.raw_inventory.get("plugins", {}).get("nginx-ingress-controller", {}).get("controller", {})
    if "resources" in raw_controller:
        inventory["plugins"]["nginx-ingress-controller"]["controller"]["resources"] = raw_controller["resources"]
    raw_webhook = cluster.raw_inventory.get("plugins", {}).get("nginx-ingress-controller", {}).get("webhook", {})
    if "resources" in raw_webhook:
        inventory["plugins"]["nginx-ingress-controller"]["webhook"]["resources"] = raw_webhook["resources"]

    return inventory


def cert_renew_enrichment(inventory: dict, cluster: KubernetesCluster) -> dict:
    # check that renewal is required for nginx
    if cluster.context.get('initial_procedure') != 'cert_renew' \
            or not cluster.procedure_inventory.get("nginx-ingress-controller"):
        return inventory

    nginx_plugin = inventory["plugins"]["nginx-ingress-controller"]

    # check that renewal is possible
    if not nginx_plugin["install"]:
        raise Exception("Certificates can not be renewed for nginx plugin since it is not installed")

    # update certificates in inventory
    nginx_plugin["controller"]["ssl"]["default-certificate"] = cluster.procedure_inventory["nginx-ingress-controller"]

    return inventory


def finalize_inventory(cluster: KubernetesCluster, inventory_to_finalize: dict) -> dict:
    # check that renewal is required for nginx
    if cluster.context.get('initial_procedure') != 'cert_renew' \
            or not cluster.procedure_inventory.get("nginx-ingress-controller"):
        return inventory_to_finalize

    if not inventory_to_finalize["plugins"].get("nginx-ingress-controller"):
        inventory_to_finalize["plugins"]["nginx-ingress-controller"] = {}

    if not inventory_to_finalize["plugins"]["nginx-ingress-controller"].get("controller"):
        inventory_to_finalize["plugins"]["nginx-ingress-controller"]["controller"] = {}

    if not inventory_to_finalize["plugins"]["nginx-ingress-controller"]["controller"].get("ssl"):
        inventory_to_finalize["plugins"]["nginx-ingress-controller"]["controller"]["ssl"] = {}

    nginx_plugin = inventory_to_finalize["plugins"]["nginx-ingress-controller"]
    nginx_plugin["controller"]["ssl"]["default-certificate"] = cluster.procedure_inventory["nginx-ingress-controller"]

    return inventory_to_finalize


def redeploy_ingress_nginx_is_needed(cluster: KubernetesCluster) -> bool:
    # redeploy ingres-nginx-controller for add/remove node procedures is needed in case:
    # 1. plugins.nginx-ingress-controller.install=true
    # 2. any balancer node exists (including as remove_node)
    # 3. all balancers have add_node/remove_node roles (added the first or removed the last balancer)
    # 4. One of following is not overriden:
    #    4.1. use-proxy-protocol
    #    4.2. ingress-nginx-ports and some from target ports
    ingress_nginx_plugin = cluster.inventory['plugins']['nginx-ingress-controller']
    balancers = [balancer for balancer in cluster.inventory['nodes'] if 'balancer' in balancer['roles']]
    if not ingress_nginx_plugin.get("install", False) or \
            not balancers or \
            any('add_node' not in node['roles'] and 'remove_node' not in node['roles'] for node in balancers):
        return False

    proxy_protocol_overriden = 'use-proxy-protocol' in cluster.raw_inventory.get('plugins', {})\
        .get('nginx-ingress-controller', {})\
        .get('config_map', {})
    http_target_port_overriden = 'http' in cluster.raw_inventory.get('services', {})\
        .get('loadbalancer', {})\
        .get('target_ports', {})
    https_target_port_overriden = 'https' in cluster.raw_inventory.get('services', {}) \
        .get('loadbalancer', {}) \
        .get('target_ports', {})
    ingress_nginx_ports_overriden = 'ports' in cluster.raw_inventory.get('plugins', {})\
        .get('nginx-ingress-controller', {})
    return not proxy_protocol_overriden or not (ingress_nginx_ports_overriden or
                                                (https_target_port_overriden and http_target_port_overriden))


def manage_custom_certificate(cluster: KubernetesCluster) -> None:
    default_cert = cluster.inventory["plugins"]["nginx-ingress-controller"]["controller"]["ssl"]\
        .get("default-certificate")
    if not default_cert:
        cluster.log.debug("No custom default ingress certificate specified, skipping...")
        return

    secret_name = "default-ingress-cert"
    secret_namespace = "kube-system"

    first_control_plane = cluster.nodes["control-plane"].get_first_member()

    # first, we need to load cert and key files to first control-plane to known locations
    with secrets.create_tls_secret_procedure(first_control_plane):
        first_control_plane.call(put_custom_certificate, default_cert=default_cert)

        # second, we need to validate cert and key using openssl
        first_control_plane.call(verify_certificate_and_key)

        # third, we need to create tls secret under well-known name
        # this certificate is already configured to be used by controller
        first_control_plane.call(secrets.renew_tls_secret,
                                 name=secret_name,
                                 namespace=secret_namespace)
    # fourth, we need to remove base path dir when the procedure is exited


def put_custom_certificate(first_control_plane: NodeGroup, default_cert: dict) -> None:
    if default_cert.get("data"):
        cert = io.StringIO(default_cert["data"]["cert"])
        key = io.StringIO(default_cert["data"]["key"])
    else:
        cert = io.StringIO(utils.read_external(default_cert["paths"]["cert"]))
        key = io.StringIO(utils.read_external(default_cert["paths"]["key"]))

    secrets.put_certificate(first_control_plane, cert, key)


def verify_certificate_and_key(first_control_plane: NodeGroup) -> None:
    if not secrets.verify_certificate(first_control_plane):
        raise Exception("Custom default ingress certificate and key are not compatible!")


class IngressNginxManifestProcessor(Processor):
    def __init__(self, logger: log.VerboseLogger, inventory: dict,
                 original_yaml_path: Optional[str] = None, destination_name: Optional[str] = None) -> None:
        super().__init__(logger, inventory, Identity('nginx-ingress-controller'), original_yaml_path, destination_name)

    def get_known_objects(self) -> List[str]:
        return [
            "Namespace_ingress-nginx",
            "ServiceAccount_ingress-nginx",
            "ServiceAccount_ingress-nginx-admission",
            "Role_ingress-nginx",
            "Role_ingress-nginx-admission",
            "ClusterRole_ingress-nginx",
            "ClusterRole_ingress-nginx-admission",
            "RoleBinding_ingress-nginx",
            "RoleBinding_ingress-nginx-admission",
            "ClusterRoleBinding_ingress-nginx",
            "ClusterRoleBinding_ingress-nginx-admission",
            "ConfigMap_ingress-nginx-controller",
            "Service_ingress-nginx-controller",
            "Service_ingress-nginx-controller-admission",
            "Deployment_ingress-nginx-controller",
            "Job_ingress-nginx-admission-create",
            "Job_ingress-nginx-admission-patch",
            "IngressClass_nginx",
            "NetworkPolicy_ingress-nginx-admission",
            "ValidatingWebhookConfiguration_ingress-nginx-admission",
        ]

    def get_enrichment_functions(self) -> List[EnrichmentFunction]:
        return [
            self.enrich_namespace_ingress_nginx,
            self.enrich_configmap_ingress_nginx_controller,
            self.add_configmap_ingress_nginx_controller,
            self.enrich_deployment_ingress_nginx_controller,
            self.enrich_ingressclass_nginx,
            self.enrich_job_ingress_nginx_admission_create,
            self.enrich_job_ingress_nginx_admission_patch,
            self.enrich_service_ingress_nginx_controller,
        ]

    def get_namespace_to_necessary_pss_profiles(self) -> Dict[str, str]:
        return {'ingress-nginx': 'privileged'}

    def enrich_namespace_ingress_nginx(self, manifest: Manifest) -> None:
        self.assign_default_pss_labels(manifest, 'ingress-nginx')

    def enrich_configmap_ingress_nginx_controller(self, manifest: Manifest) -> None:
        key = "ConfigMap_ingress-nginx-controller"
        config_map = self.inventory['plugins']['nginx-ingress-controller'].get('config_map')
        if config_map:
            source_yaml = manifest.get_obj(key, patch=True)
            data: dict = source_yaml['data']
            data.update(config_map)
            self.log.verbose(f"The {key} has been patched in 'data' "
                             f"with the data from 'plugins.nginx-ingress-controller.config_map'")

    def add_configmap_ingress_nginx_controller(self, manifest: Manifest) -> None:
        custom_headers = self.inventory['plugins']['nginx-ingress-controller'].get('custom_headers')
        if custom_headers:
            custom_headers_cm = dict(CUSTOM_HEADERS_CM)
            custom_headers_cm['data'] = custom_headers
            # Insert custom-headers ConfigMap before ingress-nginx-controller ConfigMap
            ingres_nginx_cm = manifest.key_index("ConfigMap_ingress-nginx-controller")
            self.include(manifest, ingres_nginx_cm, custom_headers_cm)
            self.log.verbose(f"The {manifest.obj_key(custom_headers_cm)} has been patched in 'data' "
                             f"with the data from 'plugins.nginx-ingress-controller.custom_headers'")

    def enrich_deployment_ingress_nginx_controller(self, manifest: Manifest) -> None:
        key = "Deployment_ingress-nginx-controller"
        source_yaml = manifest.get_obj(key, patch=True)

        self.enrich_deamonset_ingress_nginx_controller_container(manifest)

        self.enrich_image_for_container(manifest, key,
            plugin_service='controller', container_name='controller', is_init_container=False)

        self.enrich_resources_for_container(manifest, key, container_name='controller', plugin_service="controller")
        self.enrich_node_selector(manifest, key, plugin_service='controller')
        self.enrich_tolerations(manifest, key, plugin_service='controller')

        # DeamonSet spec lacks of strategy. Discard it if present.
        source_yaml['spec'].pop('strategy', None)
        # Patch kind in the last step to avoid sudden key change in log messages
        source_yaml['kind'] = 'DaemonSet'
        self.log.verbose(f"The {key} has been patched in 'kind' with 'DaemonSet'")

    def enrich_deamonset_ingress_nginx_controller_container(self, manifest: Manifest) -> None:
        key = "Deployment_ingress-nginx-controller"

        extra_args: List[str] = [
            '--watch-ingress-without-class=true'
        ]
        ssl_options = self.inventory['plugins']['nginx-ingress-controller']['controller']['ssl']

        if ssl_options['enableSslPassthrough']:
            extra_args.append('--enable-ssl-passthrough')
        if ssl_options.get('default-certificate'):
            extra_args.append('--default-ssl-certificate' + '=' + 'kube-system/default-ingress-cert')

        self.enrich_deamonset_ingress_nginx_controller_container_args(
            manifest, remove_args=['--publish-service'], extra_args=extra_args)

        container_pos, container = self.find_container_for_patch(
            manifest, key, container_name='controller', is_init_container=False)

        container['ports'] = self.inventory['plugins']['nginx-ingress-controller']['ports']
        self.log.verbose(f"The {key} has been patched in 'spec.template.spec.containers.[{container_pos}].ports' "
                         f"with the data from 'plugins.nginx-ingress-controller.ports'")

    def enrich_deamonset_ingress_nginx_controller_container_args(self, manifest: Manifest,
                                                                 *,
                                                                 remove_args: List[str],
                                                                 extra_args: List[str]) -> None:
        key = "Deployment_ingress-nginx-controller"
        self.enrich_args_for_container(manifest, key,
                                       plugin_service='controller', container_name='controller',
                                       remove_args=remove_args,
                                       extra_args=extra_args)

    def enrich_ingressclass_nginx(self, manifest: Manifest) -> None:
        key = "IngressClass_nginx"
        source_yaml = manifest.get_obj(key, patch=True)
        source_yaml['metadata'].setdefault('annotations', {})['ingressclass.kubernetes.io/is-default-class'] = 'true'
        self.log.verbose(f"The {key} has been patched in 'metadata.annotations' "
                         f"with 'ingressclass.kubernetes.io/is-default-class: true'")

    def enrich_job_ingress_nginx_admission_create(self, manifest: Manifest) -> None:
        key = "Job_ingress-nginx-admission-create"
        self.enrich_image_for_container(manifest, key,
            plugin_service='webhook', container_name='create', is_init_container=False)

        self.enrich_resources_for_container(manifest, key, container_name='create', plugin_service="webhook")

    def enrich_job_ingress_nginx_admission_patch(self, manifest: Manifest) -> None:
        key = "Job_ingress-nginx-admission-patch"
        self.enrich_image_for_container(manifest, key,
            plugin_service='webhook', container_name='patch', is_init_container=False)

        self.enrich_resources_for_container(manifest, key, container_name='patch', plugin_service="webhook")

    def enrich_service_ingress_nginx_controller(self, manifest: Manifest) -> None:
        # The method needs some rework in case of dual stack support
        key = "Service_ingress-nginx-controller"
        ip = self.inventory['services']['kubeadm']['networking']['serviceSubnet'].split('/')[0]
        if type(ipaddress.ip_address(ip)) is ipaddress.IPv6Address:
            source_yaml = manifest.get_obj(key, patch=True)
            source_yaml['spec']['ipFamilies'] = ['IPv6']
            self.log.verbose(f"The {key} has been patched in 'spec.ipFamilies' with 'IPv6'")


class V1_2_X_IngressNginxManifestProcessor(IngressNginxManifestProcessor):
    def get_enrichment_functions(self) -> List[EnrichmentFunction]:
        enrichment_functions = super().get_enrichment_functions()
        enrichment_functions.extend([
            self.exclude_webhook_resources,
            self.enrich_role_ingress_nginx,
        ])
        return enrichment_functions

    def enrich_deamonset_ingress_nginx_controller_container(self, manifest: Manifest) -> None:
        key = "Deployment_ingress-nginx-controller"

        container_pos, container = self.find_container_for_patch(
            manifest, key, container_name='controller', is_init_container=False)

        del container['volumeMounts']
        self.log.verbose(f"The 'volumeMounts' property has been removed "
                         f"from 'spec.template.spec.containers.[{container_pos}]' in the {key}")

        super().enrich_deamonset_ingress_nginx_controller_container(manifest)

    def enrich_deamonset_ingress_nginx_controller_container_args(self, manifest: Manifest,
                                                                 *,
                                                                 remove_args: List[str],
                                                                 extra_args: List[str]) -> None:
        webhook_args_remove = [
            '--validating-webhook',
            '--validating-webhook-certificate',
            '--validating-webhook-key'
        ]
        remove_args = remove_args + webhook_args_remove
        super().enrich_deamonset_ingress_nginx_controller_container_args(
            manifest, remove_args=remove_args, extra_args=extra_args)

    def enrich_job_ingress_nginx_admission_create(self, manifest: Manifest) -> None:
        return

    def enrich_job_ingress_nginx_admission_patch(self, manifest: Manifest) -> None:
        return

    def exclude_webhook_resources(self, manifest: Manifest) -> None:
        webhook_resources = [
            "ServiceAccount_ingress-nginx-admission",
            "Role_ingress-nginx-admission",
            "ClusterRole_ingress-nginx-admission",
            "RoleBinding_ingress-nginx-admission",
            "ClusterRoleBinding_ingress-nginx-admission",
            "Service_ingress-nginx-controller-admission",
            "Job_ingress-nginx-admission-create",
            "Job_ingress-nginx-admission-patch",
            "ValidatingWebhookConfiguration_ingress-nginx-admission",
        ]
        for key in webhook_resources:
            self.exclude(manifest, key)

    def enrich_role_ingress_nginx(self, manifest: Manifest) -> None:
        key = "Role_ingress-nginx"
        source_yaml = manifest.get_obj(key, patch=True)
        # TODO patch only if psp is enabled?
        api_list = source_yaml['rules']
        api_list.append(psp_ingress_nginx)
        self.log.verbose(f"The {key} has been patched in 'rules' with {psp_ingress_nginx}")


def get_ingress_nginx_manifest_processor(logger: log.VerboseLogger, inventory: dict,
                                         yaml_path: Optional[str] = None, destination: Optional[str] = None) -> Processor:
    version: str = inventory['plugins']['nginx-ingress-controller']['version']
    kwargs = {'original_yaml_path': yaml_path, 'destination_name': destination}
    if utils.minor_version(version) == 'v1.2':
        return V1_2_X_IngressNginxManifestProcessor(logger, inventory, **kwargs)

    return IngressNginxManifestProcessor(logger, inventory, **kwargs)


CUSTOM_HEADERS_CM = {
    "apiVersion": "v1",
    "kind": "ConfigMap",
    "metadata": {
        "name": "custom-headers",
        "namespace": "ingress-nginx"
    }
}

psp_ingress_nginx = {
    "apiGroups": ["extensions"],
    "resources": ["podsecuritypolicies"],
    "verbs":     ["use"],
    "resourceNames": ["oob-host-network-psp"]
}
