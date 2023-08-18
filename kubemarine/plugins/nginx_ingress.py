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
from typing import Optional, List

from kubemarine.core import utils, log
from kubemarine.core.cluster import KubernetesCluster
from kubemarine.core.group import NodeGroup
from kubemarine.plugins.manifest import Processor, EnrichmentFunction, Manifest


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


def manage_custom_certificate(cluster: KubernetesCluster) -> None:
    if not cluster.inventory["plugins"]["nginx-ingress-controller"]["controller"]["ssl"].get("default-certificate"):
        cluster.log.debug("No custom default ingress certificate specified, skipping...")
        return

    base_path = "/etc/kubernetes/custom-certs"
    certificate_path = base_path + "/cert"
    private_key_path = base_path + "/key"
    secret_name = "default-ingress-cert"
    secret_namespace = "kube-system"

    first_control_plane = cluster.nodes["control-plane"].get_first_member()
    default_cert = cluster.inventory["plugins"]["nginx-ingress-controller"]["controller"]["ssl"]["default-certificate"]

    # first, we need to load cert and key files to first control-plane to known locations
    first_control_plane.sudo(f"mkdir -p {base_path}")
    try:
        first_control_plane.call(put_custom_certificate,
                          default_cert=default_cert,
                          crt_path=certificate_path,
                          key_path=private_key_path)

        # second, we need to validate cert and key using openssl
        first_control_plane.call(verify_certificate_and_key, crt_path=certificate_path, key_path=private_key_path)

        # third, we need to create tls secret under well-known name
        # this certificate is already configured to be used by controller
        first_control_plane.call(create_tls_secret,
                          crt_path=certificate_path,
                          key_path=private_key_path,
                          name=secret_name,
                          namespace=secret_namespace)
    finally:
        # fourth, we need to remove base path dir
        first_control_plane.sudo(f"rm -rf {base_path}")


def put_custom_certificate(first_control_plane: NodeGroup, default_cert: dict, crt_path: str, key_path: str) -> None:
    if default_cert.get("data"):
        cert = io.StringIO(default_cert["data"]["cert"])
        key = io.StringIO(default_cert["data"]["key"])
    else:
        cert = io.StringIO(utils.read_external(default_cert["paths"]["cert"]))
        key = io.StringIO(utils.read_external(default_cert["paths"]["key"]))

    first_control_plane.put(cert, crt_path, sudo=True)
    first_control_plane.put(key, key_path, sudo=True)


def verify_certificate_and_key(first_control_plane: NodeGroup, crt_path: str, key_path: str) -> None:
    crt_md5 = first_control_plane.sudo(f"openssl x509 -noout -modulus -in {crt_path} | openssl md5").get_simple_out()
    key_md5 = first_control_plane.sudo(f"openssl rsa -noout -modulus -in {key_path} | openssl md5").get_simple_out()
    if crt_md5 != key_md5:
        raise Exception("Custom default ingress certificate and key are not compatible!")


def create_tls_secret(first_control_plane: NodeGroup, crt_path: str, key_path: str, name: str, namespace: str) -> None:
    first_control_plane.sudo(f"kubectl create secret tls {name} --key {key_path} --cert {crt_path} -n {namespace} "
                      f"--dry-run -o yaml | sudo kubectl apply -f -", timeout=300)


class IngressNginxManifestProcessor(Processor):
    def __init__(self, logger: log.VerboseLogger, inventory: dict,
                 original_yaml_path: Optional[str] = None, destination_name: Optional[str] = None) -> None:
        super().__init__(logger, inventory, 'nginx-ingress-controller', original_yaml_path, destination_name)

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

    def enrich_namespace_ingress_nginx(self, manifest: Manifest) -> None:
        key = "Namespace_ingress-nginx"
        rbac = self.inventory['rbac']
        if rbac['admission'] == 'pss' and rbac['pss']['pod-security'] == 'enabled' \
                and rbac['pss']['defaults']['enforce'] != 'privileged':
            self.assign_default_pss_labels(manifest, key, 'privileged')

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

        container_pos, container = self.find_container_for_patch(
            manifest, key, container_name='controller', is_init_container=False)
        self.enrich_deamonset_ingress_nginx_controller_container(container_pos, container)

        self.enrich_image_for_container(manifest, key,
            plugin_service='controller', container_name='controller', is_init_container=False)

        self.enrich_resources_for_container(manifest, key, container_name='controller', plugin_service="controller")
        self.enrich_node_selector(manifest, key, plugin_service='controller')
        self.enrich_tolerations(manifest, key, plugin_service='controller')

        # Patch kind in the last step to avoid sudden key change in log messages
        source_yaml['kind'] = 'DaemonSet'
        self.log.verbose(f"The {key} has been patched in 'kind' with 'DaemonSet'")

    def enrich_deamonset_ingress_nginx_controller_container(self, container_pos: int, container: dict) -> None:
        key = "Deployment_ingress-nginx-controller"
        container_args = container['args']
        for i, arg in enumerate(container_args):
            if arg.startswith('--publish-service='):
                del container_args[i]
                self.log.verbose(f"The {arg!r} argument has been removed from "
                                 f"'spec.template.spec.containers.[{container_pos}].args' in the {key}")
                break
        else:
            raise Exception("Failed to find '--publish-service' argument in ingress-nginx-controller container specification.")

        extra_args: List[tuple] = [
            ('--watch-ingress-without-class=', 'true')
        ]
        ssl_options = self.inventory['plugins']['nginx-ingress-controller']['controller']['ssl']
        additional_args = self.inventory['plugins']['nginx-ingress-controller']['controller'].get('args')

        if additional_args:
            for arg in additional_args:
                pars_arg = arg.split('=')
                for i, container_arg in enumerate(container_args):
                    if container_arg.startswith(pars_arg[0]):
                       raise Exception(
                           f"{pars_arg[0]!r} argument is already defined in ingress-nginx-controller container specification.")
                else:
                    container_args.append(arg)
                    self.log.verbose(f"The {arg!r} argument has been added to "
                                     f"'spec.template.spec.containers.[{container_pos}].args' in the {key}")

        if ssl_options['enableSslPassthrough']:
            extra_args.append(('--enable-ssl-passthrough',))
        if ssl_options.get('default-certificate'):
            extra_args.append(('--default-ssl-certificate=', 'kube-system/default-ingress-cert'))

        for extra_arg in extra_args:
            for i, arg in enumerate(container_args):
                if arg.startswith(extra_arg[0]):
                    raise Exception(
                        f"{extra_arg[0]!r} argument is already defined in ingress-nginx-controller container specification.")
            else:
                arg = extra_arg[0]
                if len(extra_arg) > 1:
                    arg += extra_arg[1]
                container_args.append(arg)
                self.log.verbose(f"The {arg!r} argument has been added to "
                                 f"'spec.template.spec.containers.[{container_pos}].args' in the {key}")

        container['ports'] = self.inventory['plugins']['nginx-ingress-controller']['ports']
        self.log.verbose(f"The {key} has been patched in 'spec.template.spec.containers.[{container_pos}].ports' "
                         f"with the data from 'plugins.nginx-ingress-controller.ports'")

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

    def enrich_configmap_ingress_nginx_controller(self, manifest: Manifest) -> None:
        key = "ConfigMap_ingress-nginx-controller"
        source_yaml = manifest.get_obj(key, patch=True)
        # For some reason, we took manifest for Digital Ocean, removed use-proxy-protocol: "true" property,
        # but left service.beta.kubernetes.io/do-loadbalancer-enable-proxy-protocol: "true" annotation
        # in ingress-nginx-controller Service.
        # The behaviour is left as-is for compatibility.
        # For v.1.4.0 we took the default manifest which lacks of the mentioned properties.
        del source_yaml['data']['use-proxy-protocol']
        self.log.verbose(f"The 'use-proxy-protocol' property has been removed from 'data' in the {key}")
        super().enrich_configmap_ingress_nginx_controller(manifest)

    def enrich_deamonset_ingress_nginx_controller_container(self, container_pos: int, container: dict) -> None:
        key = "Deployment_ingress-nginx-controller"
        container_args = container['args']
        webhook_args_remove = [
            '--validating-webhook=',
            '--validating-webhook-certificate=',
            '--validating-webhook-key='
        ]
        for arg_remove in webhook_args_remove:
            for i, arg in enumerate(container_args):
                if arg.startswith(arg_remove):
                    del container_args[i]
                    self.log.verbose(f"The {arg!r} argument has been removed from "
                                     f"'spec.template.spec.containers.[{container_pos}].args' in the {key}")
                    break

        del container['volumeMounts']
        self.log.verbose(f"The 'volumeMounts' property has been removed "
                         f"from 'spec.template.spec.containers.[{container_pos}]' in the {key}")

        super().enrich_deamonset_ingress_nginx_controller_container(container_pos, container)

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
