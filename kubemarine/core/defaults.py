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
import re
from importlib import import_module
from copy import deepcopy
from typing import Optional, Dict, Any, Tuple, List

import yaml

from kubemarine.core.cluster import KubernetesCluster
from kubemarine.core.errors import KME
from kubemarine import jinja, keepalived, haproxy
from kubemarine.core import utils, static, log, os
from kubemarine.core.yaml_merger import default_merger
from kubemarine.cri.containerd import contains_old_format_properties

# All enrichment procedures should not connect to any node.
# The information about nodes should be collected within KubernetesCluster#detect_nodes_context().
DEFAULT_ENRICHMENT_FNS = [
    "kubemarine.core.schema.verify_inventory",
    "kubemarine.core.defaults.merge_defaults",
    "kubemarine.kubernetes.verify_initial_version",
    "kubemarine.admission.enrich_default_admission",
    "kubemarine.kubernetes.add_node_enrichment",
    "kubemarine.core.defaults.calculate_node_names",
    "kubemarine.kubernetes.remove_node_enrichment",
    "kubemarine.controlplane.controlplane_node_enrichment",
    "kubemarine.core.defaults.append_controlplain",
    "kubemarine.kubernetes.enrich_upgrade_inventory",
    "kubemarine.kubernetes.enrich_restore_inventory",
    "kubemarine.core.defaults.compile_inventory",
    "kubemarine.core.defaults.manage_true_false_values",
    "kubemarine.plugins.enrich_upgrade_inventory",
    "kubemarine.packages.enrich_inventory",
    "kubemarine.packages.enrich_upgrade_inventory",
    "kubemarine.packages.enrich_migrate_cri_inventory",
    "kubemarine.packages.enrich_inventory_apply_defaults",
    "kubemarine.thirdparties.enrich_upgrade_inventory",
    "kubemarine.thirdparties.enrich_restore_inventory",
    "kubemarine.thirdparties.enrich_migrate_cri_inventory",
    "kubemarine.admission.manage_enrichment",
    "kubemarine.cri.containerd.enrich_migrate_cri_inventory",
    "kubemarine.core.defaults.apply_registry",
    "kubemarine.cri.enrich_upgrade_inventory",
    "kubemarine.core.defaults.verify_node_names",
    "kubemarine.core.defaults.apply_defaults",
    "kubemarine.keepalived.enrich_inventory_apply_defaults",
    "kubemarine.haproxy.enrich_inventory",
    "kubemarine.kubernetes.enrich_inventory",
    "kubemarine.admission.enrich_inventory",
    "kubemarine.kubernetes_accounts.enrich_inventory",
    "kubemarine.plugins.calico.enrich_inventory",
    "kubemarine.plugins.nginx_ingress.cert_renew_enrichment",
    "kubemarine.plugins.nginx_ingress.enrich_inventory",
    "kubemarine.plugins.local_path_provisioner.enrich_inventory",
    "kubemarine.plugins.kubernetes_dashboard.enrich_inventory",
    "kubemarine.core.defaults.calculate_nodegroups",
    "kubemarine.keepalived.enrich_inventory_calculate_nodegroup",
    "kubemarine.thirdparties.enrich_inventory_apply_defaults",
    "kubemarine.system.verify_inventory",
    "kubemarine.system.enrich_etc_hosts",
    "kubemarine.packages.enrich_inventory_include_all",
    "kubemarine.audit.verify_inventory",
    "kubemarine.plugins.enrich_inventory",
    "kubemarine.plugins.verify_inventory",
    "kubemarine.plugins.builtin.verify_inventory",
    "kubemarine.k8s_certs.renew_verify",
    "kubemarine.cri.enrich_inventory",
    "kubemarine.system.enrich_kernel_modules"
]

supported_defaults = {
    'rbac': {
        'account_defaults': 'accounts'
    },
    'node_defaults': 'nodes',
}

invalid_node_name_regex = re.compile("[^a-z-.\\d]", re.M)
escaped_expression_regex = re.compile('({%[\\s*|]raw[\\s*|]%}.*?{%[\\s*|]endraw[\\s*|]%})', re.M)
jinja_query_regex = re.compile("{{ .* }}", re.M)


def apply_defaults(inventory: dict, cluster: KubernetesCluster) -> dict:
    recursive_apply_defaults(supported_defaults, inventory)

    for i, node in enumerate(inventory["nodes"]):
        address = cluster.get_access_address_from_node(node)

        # we definitely know how to connect
        cluster.inventory["nodes"][i]["connect_to"] = address

        if not cluster.context["nodes"].get(address):
            cluster.context["nodes"][address] = {}

        if address not in cluster.ips["all"]:
            cluster.ips['all'].append(address)

        for role in node.get("roles"):
            if role not in cluster.roles:
                cluster.roles.append(role)
                cluster.ips[role] = []
            if address not in cluster.ips[role]:
                cluster.ips[role].append(address)

    return inventory


def apply_registry(inventory: dict, cluster: KubernetesCluster) -> dict:

    if not inventory.get('registry'):
        cluster.log.verbose('Unified registry is not used')
        return inventory

    thirdparties_address = None
    containerd_endpoints = None
    protocol = None

    # registry contains either 'endpoints' or 'address' that is validated by JSON schema.
    if inventory['registry'].get('endpoints'):
        registry_mirror_address, containerd_endpoints, thirdparties_address = apply_registry_endpoints(inventory)
    else:
        if inventory['registry'].get('docker_port'):
            registry_mirror_address = "%s:%s" % (inventory['registry']['address'], inventory['registry']['docker_port'])
        else:
            registry_mirror_address = inventory['registry']['address']

        protocol = 'http'
        if inventory['registry'].get('ssl', False):
            protocol = 'https'

        if inventory['registry'].get('webserver', False):
            thirdparties_address = f"{protocol}://{inventory['registry']['address']}"

    # Patch kubeadm imageRepository and plugin_defaults registry
    if cluster.raw_inventory.get('services', {}).get('kubeadm', {}).get('imageRepository') is None:
        inventory['services']['kubeadm']["imageRepository"] = registry_mirror_address
    inventory['plugin_defaults']['installation'].setdefault('registry', registry_mirror_address)

    cri_impl = inventory['services']['cri']['containerRuntime']

    if cri_impl == "docker" and inventory['registry'].get('endpoints'):
        raise KME('KME0007')

    if cri_impl == "docker":

        if protocol == 'http':
            if inventory['services']['cri']['dockerConfig'].get("insecure-registries") is None:
                inventory['services']['cri']['dockerConfig']["insecure-registries"] = []
            insecure_registries = inventory['services']['cri']['dockerConfig']["insecure-registries"]
            insecure_registries.append(registry_mirror_address)
            inventory['services']['cri']['dockerConfig']["insecure-registries"] = list(set(insecure_registries))

        if inventory['services']['cri']['dockerConfig'].get("registry-mirrors") is None:
            inventory['services']['cri']['dockerConfig']["registry-mirrors"] = []

        registry_mirrors = inventory['services']['cri']['dockerConfig']["registry-mirrors"]
        registry_mirrors.append(f"{protocol}://{registry_mirror_address}")
        inventory['services']['cri']['dockerConfig']["registry-mirrors"] = list(set(registry_mirrors))

    elif cri_impl == "containerd":
        if not containerd_endpoints:
            containerd_endpoints = ["%s://%s" % (protocol, registry_mirror_address)]

        old_format_result, _ = contains_old_format_properties(inventory)
        # todo remove p3_reconfigure_registries after next release
        if old_format_result or not cluster.context.get('p3_reconfigure_registries', True):
            # Add registry info in old format
            registry_section = f'plugins."io.containerd.grpc.v1.cri".registry.mirrors."{registry_mirror_address}"'
            containerd_config = inventory['services']['cri']['containerdConfig']
            if not containerd_config.get(registry_section):
                containerd_config[registry_section] = {
                    'endpoint': containerd_endpoints
                }
        else:
            # Add registry info in new format
            old_registry_config = inventory['services']['cri'].get('containerdRegistriesConfig', {})
            inventory['services']['cri']['containerdRegistriesConfig'] = {registry_mirror_address: {
                                     f'host."{endpoint}"': {'capabilities': ['pull', 'resolve']}
                                     for endpoint in containerd_endpoints
                                 }}
            default_merger.merge(inventory['services']['cri']['containerdRegistriesConfig'], old_registry_config)

    from kubemarine import thirdparties

    if thirdparties_address:
        for destination, config in inventory['services']['thirdparties'].items():
            if not thirdparties.is_default_thirdparty(destination) or isinstance(config, str) or 'source' in config:
                continue

            source, sha1 = thirdparties.get_default_thirdparty_identity(cluster.inventory, destination, in_public=False)
            source = source.format(registry=thirdparties_address)
            config['source'] = source
            if 'sha1' not in config:
                config['sha1'] = sha1

    return inventory


def apply_registry_endpoints(inventory: dict) -> Tuple[str, List[str], Optional[str]]:

    if not inventory['registry'].get('mirror_registry'):
        inventory['registry']['mirror_registry'] = 'registry.cluster.local'

    registry_mirror_address = inventory['registry']['mirror_registry']

    # todo Currently registry.endpoints is used only for containerd registry mirrors, but it can be provided explicitly.
    #  Probably we could make endpoints optional in this case.
    containerd_endpoints = inventory['registry']['endpoints']
    thirdparties_address = inventory['registry'].get('thirdparties')

    return registry_mirror_address, containerd_endpoints, thirdparties_address


def append_controlplain(inventory: dict, cluster: Optional[KubernetesCluster]) -> dict:

    if inventory.get('control_plain', {}).get('internal') and inventory.get('control_plain', {}).get('external'):
        if cluster:
            cluster.log.verbose('Control plains are set manually, nothing to detect.')
        return inventory

    if cluster:
        cluster.log.verbose('Detecting control plains...')

    # calculate controlplain ips
    internal_address: Optional[str] = None
    internal_address_source: Optional[str] = None
    external_address: Optional[str] = None
    external_address_source: Optional[str] = None

    balancer_names = keepalived.get_all_balancer_names(inventory, final=True)
    # vrrp_ip section is not enriched yet
    # If no VRRP IPs or no balancers are configured, Keepalived is not enabled.
    if inventory.get('vrrp_ips') and balancer_names:
        for i, item in enumerate(inventory['vrrp_ips']):
            if isinstance(item, str):
                if internal_address is None:
                    internal_address = item
                    internal_address_source = 'vrrp_ip[%s]' % i
            else:
                if haproxy.is_vrrp_not_bind(item):
                    continue
                final_hosts = item.get('hosts', balancer_names)
                # There is a small gap here.
                # The check is invoked when inventory is not yet compiled, so checking names for equality is not fair.
                if not any((host['name'] if isinstance(host, dict) else host) in balancer_names
                           for host in final_hosts):
                    continue
                if internal_address is None or item.get('control_endpoint', False):
                    internal_address = item['ip']
                    internal_address_source = 'vrrp_ip[%s]' % i
                if item.get('floating_ip') and (external_address is None or item.get('control_endpoint', False)):
                    external_address = item['floating_ip']
                    external_address_source = 'vrrp_ip[%s]' % i

    if internal_address is not None and external_address is None and cluster:
        cluster.log.warning('VRRP_IPs has an internal address, but do not have an external one. Your configuration may be incorrect. Trying to handle this problem automatically...')

    if internal_address is None or external_address is None:
        # 'master' role is not deleted due to unit tests are not refactored
        for role in ['balancer', 'control-plane', 'master']:
            # nodes are not compiled to groups yet
            for node in inventory['nodes']:
                if role in node['roles'] and 'remove_node' not in node['roles']:
                    if internal_address is None or node.get('control_endpoint', False):
                        internal_address = node['internal_address']
                        internal_address_source = f"{role} \"{node['name']}\""
                    if node.get('address') and (external_address is None or node.get('control_endpoint', False)):
                        external_address = node['address']
                        external_address_source = f"{role} \"{node['name']}\""

    if external_address is None:
        if cluster:
            cluster.log.warning('Failed to detect external control plain. Something may work incorrect!')
        external_address = internal_address

    if cluster:
        cluster.log.debug('Control plains:\n   Internal: %s (%s)\n   External: %s (%s)' % (internal_address, internal_address_source, external_address, external_address_source))

    # apply controlplain ips
    if not inventory.get('control_plain'):
        inventory['control_plain'] = {}

    if not inventory['control_plain'].get('internal'):
        inventory['control_plain']['internal'] = internal_address

    if not inventory['control_plain'].get('external'):
        inventory['control_plain']['external'] = external_address

    return inventory


def recursive_apply_defaults(defaults: dict, section: dict) -> None:
    for key, value in defaults.items():
        if isinstance(value, dict) and section.get(key) is not None and section[key]:
            recursive_apply_defaults(value, section[key])
        # check if target section exists and not empty
        elif section.get(value) is not None:
            for i, custom_value in enumerate(section[value]):
                # copy defaults as new dict, to avoid problems with memory links
                default_value = deepcopy(section[key])

                # update defaults with custom-defined node configs
                # TODO: Use deepmerge instead of update
                default_value.update(custom_value)

                # replace old node config with merged one
                section[value][i] = default_value


def calculate_node_names(inventory: dict, cluster: KubernetesCluster) -> dict:
    roles_iterators: Dict[str, int] = {}
    for i, node in enumerate(inventory['nodes']):
        # 'master' role is not deleted because calculate_node_names() can be run over initial inventory,
        # that still supports the old role.
        for role_name in ['control-plane', 'master', 'worker', 'balancer']:
            if role_name in node['roles']:
                # The idea is this:
                # If the name is already specified, we must skip this node,
                # however, we must consider that we already have a node of this type
                # and increase this type iterator
                # As a result, we get such an algorithm. For example, with the following inventory:
                #
                # - name: k8s-control-plane-1, roles: ['control-plane']
                # - roles: ['control-plane']
                # - name: k8s-control-plane-3, roles: ['control-plane']
                #
                # We should get the following calculation result:
                #
                # - name: k8s-control-plane-1, roles: ['control-plane']
                # - name: control-plane-2, roles: ['control-plane']
                # - name: k8s-control-plane-3, roles: ['control-plane']
                #
                role_i = roles_iterators.get(role_name, 1)
                roles_iterators[role_name] = role_i + 1
                if node.get('name') is None:
                    if role_name == 'master':
                        role_name = 'control-plane'
                    new_name = '%s-%s' % (role_name, role_i)
                    cluster.log.debug(f"Assigning name {new_name} to node {cluster.get_access_address_from_node(node)}")
                    node['name'] = new_name
    return inventory


def verify_node_names(inventory: dict, _: KubernetesCluster) -> dict:
    known_names = []
    for i, node in enumerate(inventory['nodes']):
        node_name = node['name']
        if node_name in known_names:
            raise Exception('Node name %s is duplicated in configfile' % node_name)
        if re.findall(invalid_node_name_regex, node_name):
            raise Exception('Node name \"%s\" contains invalid characters. A DNS-1123 subdomain must consist of lower '
                            'case alphanumeric characters, \'-\' or \'.\'' % node_name)
        known_names.append(node_name)
    return inventory


def calculate_nodegroups(inventory: dict, cluster: KubernetesCluster) -> dict:
    for role in cluster.ips.keys():
        cluster.nodes[role] = cluster.make_group(cluster.ips[role])
    return inventory


def merge_defaults(inventory: dict, cluster: KubernetesCluster) -> dict:
    base_inventory = deepcopy(static.DEFAULTS)

    inventory = default_merger.merge(base_inventory, inventory)
    # it is necessary to temporary put half-compiled inventory to cluster inventory field
    cluster._inventory = inventory
    return inventory


def enrich_inventory(cluster: KubernetesCluster, inventory: dict,
                     make_dumps: bool = True, enrichment_functions: List[str] = None) -> dict:
    if not enrichment_functions:
        enrichment_functions = DEFAULT_ENRICHMENT_FNS

    # run required fields calculation
    for enrichment_fn in enrichment_functions:
        fn_package_name, fn_method_name = enrichment_fn.rsplit('.', 1)
        mod = import_module(fn_package_name)
        cluster.log.verbose('Calling fn "%s"' % enrichment_fn)
        inventory = getattr(mod, fn_method_name)(inventory, cluster)

    cluster.log.verbose('Enrichment finished!')

    if make_dumps:
        from kubemarine import controlplane
        inventory_for_dump = controlplane.controlplane_finalize_inventory(cluster, prepare_for_dump(inventory))
        utils.dump_file(cluster, yaml.dump(inventory_for_dump, ), "cluster.yaml")

    return inventory


def compile_inventory(inventory: dict, cluster: KubernetesCluster) -> dict:

    # convert references in yaml to normal values
    iterations = 100
    root = deepcopy(inventory)
    root['globals'] = static.GLOBALS
    root['env'] = os.Environ()

    while iterations > 0:

        cluster.log.verbose('Inventory is not rendered yet...')
        inventory = compile_object(cluster.log, inventory, root)

        temp_dump = yaml.dump(inventory)

        # remove golang specific
        temp_dump = re.sub(escaped_expression_regex, '', temp_dump.replace('\n', ''))

        # it is necessary to carry out several iterations,
        # in case we have dynamic variables that reference each other
        if '{{' in temp_dump or '{%' in temp_dump:
            iterations -= 1
        else:
            iterations = 0

    inventory = compile_object(cluster.log, inventory, root, ignore_jinja_escapes=False)

    from kubemarine import controlplane
    inventory_for_dump = controlplane.controlplane_finalize_inventory(cluster, prepare_for_dump(inventory))
    merged_inventory = yaml.dump(inventory_for_dump)
    utils.dump_file(cluster, merged_inventory, "cluster_precompiled.yaml")

    return inventory


def compile_object(logger: log.EnhancedLogger, struct: Any, root: dict, ignore_jinja_escapes: bool = True) -> Any:
    if isinstance(struct, list):
        new_struct = []
        for i, v in enumerate(struct):
            struct[i] = compile_object(logger, v, root, ignore_jinja_escapes=ignore_jinja_escapes)
            # delete empty list entries, which can appear after jinja compilation
            if struct[i] != '':
                new_struct.append(struct[i])
        struct = new_struct
    elif isinstance(struct, dict):
        for k, v in struct.items():
            struct[k] = compile_object(logger, v, root, ignore_jinja_escapes=ignore_jinja_escapes)
    elif isinstance(struct, str) and ('{{' in struct or '{%' in struct):
        struct = compile_string(logger, struct, root, ignore_jinja_escapes=ignore_jinja_escapes)

    return struct


def compile_string(logger: log.EnhancedLogger, struct: str, root: dict,
                   ignore_jinja_escapes: bool = True) -> str:
    logger.verbose("Rendering \"%s\"" % struct)

    if ignore_jinja_escapes:
        iterator = escaped_expression_regex.finditer(struct)
        struct = re.sub(escaped_expression_regex, '', struct)
        struct = jinja.new(logger, True, root).from_string(struct).render(**root)

        # TODO this does not work for {raw}{jinja}{raw}{jinja}
        for match in iterator:
            span = match.span()
            struct = struct[:span[0]] + match.group() + struct[span[0]:]
    else:
        struct = jinja.new(logger, True, root).from_string(struct).render(**root)

    logger.verbose("\tRendered as \"%s\"" % struct)
    return struct


def escape_jinja_characters_for_inventory(cluster: KubernetesCluster, obj: Any) -> Any:
    if isinstance(obj, dict):
        for key, value in obj.items():
            obj[key] = escape_jinja_characters_for_inventory(cluster, value)
    elif isinstance(obj, list):
        for key, value in enumerate(obj):
            obj[key] = escape_jinja_characters_for_inventory(cluster, value)
    elif isinstance(obj, str):
        obj = _escape_jinja_character(obj)
    return obj


def _escape_jinja_character(value: str) -> str:
    if '{{' in value and '}}' in value and re.search(jinja_query_regex, value):
        matches = re.findall(jinja_query_regex, value)
        for match in matches:
            # TODO: rewrite to correct way of match replacement: now it can cause "{raw}{raw}xxx.." circular bug
            value = value.replace(match, '{% raw %}'+match+'{% endraw %}')
    return value


def prepare_for_dump(inventory: dict, copy: bool = True) -> dict:
    # different preparations before the inventory can be dumped

    if copy:
        dump_inventory = deepcopy(inventory)
    else:
        dump_inventory = inventory

    return dump_inventory


def manage_true_false_values(inventory: dict, _: KubernetesCluster) -> dict:
    # Check undefined values for plugin.name.install and convert it to bool
    for plugin_name, plugin_item in inventory["plugins"].items():
        # Check install value
        if 'install' not in plugin_item:
            continue
        value = utils.strtobool(plugin_item.get('install', False), f"plugin.{plugin_name}.install")
        plugin_item['install'] = value
    return inventory
