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
from typing import Optional, List, Dict

from textwrap import dedent
import yaml

from kubemarine.core import utils, log
from kubemarine.core.cluster import KubernetesCluster, EnrichmentStage, enrichment
from kubemarine.core.group import NodeGroup
from kubemarine.kubernetes import secrets
from kubemarine.plugins.manifest import Processor, EnrichmentFunction, Manifest, Identity

ERROR_CERT_RENEW_NOT_INSTALLED = "Certificates can not be renewed for nginx plugin since it is not installed"


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


@enrichment(EnrichmentStage.FULL)
def enrich_inventory(cluster: KubernetesCluster) -> None:
    inventory = cluster.inventory
    if not inventory["plugins"]["nginx-ingress-controller"]["install"]:
        return

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


@enrichment(EnrichmentStage.PROCEDURE, procedures=['cert_renew'])
def cert_renew_enrichment(cluster: KubernetesCluster) -> None:
    # check that renewal is required for nginx
    procedure_nginx_cert = cluster.procedure_inventory.get("nginx-ingress-controller", {})
    if not procedure_nginx_cert:
        return

    # update certificates in inventory
    cluster.inventory.setdefault("plugins", {}).setdefault("nginx-ingress-controller", {}) \
        .setdefault("controller", {}).setdefault("ssl", {})["default-certificate"] \
        = utils.deepcopy_yaml(procedure_nginx_cert)


@enrichment(EnrichmentStage.PROCEDURE, procedures=['cert_renew'])
def verify_cert_renew(cluster: KubernetesCluster) -> None:
    procedure_nginx_cert = cluster.procedure_inventory.get("nginx-ingress-controller", {})
    # check that renewal is possible
    if procedure_nginx_cert and not cluster.inventory["plugins"]["nginx-ingress-controller"]["install"]:
        raise Exception(ERROR_CERT_RENEW_NOT_INSTALLED)


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
            self.enrich_service_account_secret,
            self.enrich_service_account,
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

    def enrich_service_account_secret(self, manifest: Manifest) -> None:
        new_yaml = yaml.safe_load(service_account_secret)

        service_account_key = "ServiceAccount_ingress-nginx"
        service_account_index = manifest.all_obj_keys().index(service_account_key) \
            if service_account_key in manifest.all_obj_keys() else -1

        self.include(manifest, service_account_index + 1, new_yaml)

    def enrich_service_account(self, manifest: Manifest) -> None:
        key = "ServiceAccount_ingress-nginx"
        source_yaml = manifest.get_obj(key, patch=True)
        source_yaml['automountServiceAccountToken'] = False

    def enrich_deployment_ingress_nginx_controller(self, manifest: Manifest) -> None:
        key = "Deployment_ingress-nginx-controller"
        source_yaml = manifest.get_obj(key, patch=True)
        service_account_name = "ingress-nginx"
        self.enrich_volume_and_volumemount(source_yaml, service_account_name)
        self.log.verbose(f"The {key} has been updated to include the new secret volume and mount.")

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
            manifest, remove_args=['--publish-service','--enable-metrics'], extra_args=extra_args)

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
        if utils.isipv(ip, [6]):
            source_yaml = manifest.get_obj(key, patch=True)
            source_yaml['spec']['ipFamilies'] = ['IPv6']
            self.log.verbose(f"The {key} has been patched in 'spec.ipFamilies' with 'IPv6'")


CUSTOM_HEADERS_CM = {
    "apiVersion": "v1",
    "kind": "ConfigMap",
    "metadata": {
        "name": "custom-headers",
        "namespace": "ingress-nginx"
    }
}

service_account_secret = dedent("""\
    apiVersion: v1
    kind: Secret
    metadata:
      name: ingress-nginx-token
      namespace: ingress-nginx
      annotations:
        kubernetes.io/service-account.name: ingress-nginx
    type: kubernetes.io/service-account-token  
""")