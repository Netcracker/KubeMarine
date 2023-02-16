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
from typing import Optional

import yaml

from kubemarine.core.cluster import KubernetesCluster
from kubemarine.core.errors import KME
from kubemarine import jinja
from kubemarine.core import utils, static
from kubemarine.core.yaml_merger import default_merger

# All enrichment procedures should not connect to any node.
# The information about nodes should be collected within KubernetesCluster#detect_nodes_context().
DEFAULT_ENRICHMENT_FNS = [
    "kubemarine.core.schema.verify_inventory",
    "kubemarine.core.defaults.merge_defaults",
    "kubemarine.kubernetes.add_node_enrichment",
    "kubemarine.kubernetes.remove_node_enrichment",
    "kubemarine.controlplane.controlplane_node_enrichment",
    "kubemarine.core.defaults.append_controlplain",
    "kubemarine.kubernetes.enrich_upgrade_inventory",
    "kubemarine.plugins.enrich_upgrade_inventory",
    "kubemarine.packages.enrich_inventory_associations",
    "kubemarine.packages.enrich_inventory_packages",
    "kubemarine.system.enrich_upgrade_inventory",
    "kubemarine.core.defaults.compile_inventory",
    "kubemarine.core.defaults.manage_true_false_values",
    "kubemarine.admission.manage_enrichment",
    "kubemarine.thirdparties.enrich_inventory_apply_upgrade_defaults",
    "kubemarine.procedures.migrate_cri.enrich_inventory",
    "kubemarine.core.defaults.apply_registry",
    "kubemarine.core.defaults.calculate_node_names",
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
    "kubemarine.core.defaults.calculate_nodegroups",
    "kubemarine.keepalived.enrich_inventory_calculate_nodegroup",
    "kubemarine.thirdparties.enrich_inventory_apply_defaults",
    "kubemarine.system.verify_inventory",
    "kubemarine.system.enrich_etc_hosts",
    "kubemarine.packages.enrich_inventory_include_all",
    "kubemarine.audit.verify_inventory",
    "kubemarine.plugins.enrich_inventory",
    "kubemarine.plugins.verify_inventory",
    "kubemarine.coredns.enrich_add_hosts_config",
    "kubemarine.k8s_certs.renew_verify",
    "kubemarine.cri.enrich_inventory"
]

supported_defaults = {
    'rbac': {
        'account_defaults': 'accounts'
    },
    'node_defaults': 'nodes',
    'plugin_defaults': 'plugins',
}

invalid_node_name_regex = re.compile("[^a-z-.\\d]", re.M)
escaped_expression_regex = re.compile('({%[\\s*|]raw[\\s*|]%}.*?{%[\\s*|]endraw[\\s*|]%})', re.M)
jinja_query_regex = re.compile("{{ .* }}", re.M)


def apply_defaults(inventory, cluster: KubernetesCluster):
    recursive_apply_defaults(supported_defaults, inventory)

    for i, node in enumerate(inventory["nodes"]):
        address = cluster.get_access_address_from_node(node)

        # we have definitely know how to connect
        cluster.inventory["nodes"][i]["connect_to"] = address
        cluster.inventory["nodes"][i]["connection"] = cluster.make_group([address])

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


def apply_registry(inventory, cluster):

    if not inventory.get('registry'):
        cluster.log.verbose('Unified registry is not used')
        return inventory

    thirdparties_address = None
    containerd_endpoints = None
    protocol = None

    # registry contains either 'endpoints' or 'address' that is validated by JSON schema.
    if inventory['registry'].get('endpoints'):
        registry_mirror_address, containerd_endpoints, thirdparties_address = apply_registry_endpoints(inventory, cluster)
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

    # Patch kubeadm imageRepository
    if not inventory['services']['kubeadm'].get('imageRepository'):
        inventory['services']['kubeadm']["imageRepository"] = registry_mirror_address

    # it is necessary to convert URIs from quay.io/xxx:v1 to example.com:XXXX/xxx:v1
    if inventory.get('plugin_defaults') is None:
        inventory['plugin_defaults'] = {}
    if inventory['plugin_defaults'].get('installation') is None:
        inventory['plugin_defaults']['installation'] = {}
    if inventory['plugin_defaults']['installation'].get('registry') is None:
        inventory['plugin_defaults']['installation']['registry'] = registry_mirror_address

    # The following section rewrites DEFAULT plugins registries and do not touches user-defined registries in plugins
    # This section required, because plugins defaults contains default non-docker registries and method
    # "kubemarine.core.defaults.recursive_apply_defaults" will not overwrite this default registries, because it can not
    # distinguish default from user-defined.
    # Also, this part of code supports plugin_defaults inventory section and applies everything in accordance with the
    # priority of the registries.
    for plugin_name, plugin_params in cluster.inventory['plugins'].items():
        if cluster.inventory['plugins'][plugin_name].get('installation') is None:
            cluster.inventory['plugins'][plugin_name]['installation'] = {}
        if cluster.raw_inventory.get('plugins', {}).get(plugin_name, {}).get('installation', {}).get('registry') is None:
            cluster.inventory['plugins'][plugin_name]['installation']['registry'] = inventory['plugin_defaults']['installation']['registry']

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
        registry_section = f'plugins."io.containerd.grpc.v1.cri".registry.mirrors."{registry_mirror_address}"'

        if not inventory['services']['cri']['containerdConfig'].get(registry_section):
            if not containerd_endpoints:
                containerd_endpoints = ["%s://%s" % (protocol, registry_mirror_address)]

            inventory['services']['cri']['containerdConfig'][registry_section] = {
                'endpoint': containerd_endpoints
            }

        effective_kubernetes_version = ".".join(inventory['services']['kubeadm']['kubernetesVersion'].split('.')[0:2])
        pause_version = cluster.globals['compatibility_map']['software']['pause'][effective_kubernetes_version]['version']
        if not inventory['services']['cri']['containerdConfig'].get('plugins."io.containerd.grpc.v1.cri"'):
            inventory['services']['cri']['containerdConfig']['plugins."io.containerd.grpc.v1.cri"'] = {}
        if not inventory['services']['cri']['containerdConfig']['plugins."io.containerd.grpc.v1.cri"'].get('sandbox_image'):
            inventory['services']['cri']['containerdConfig']['plugins."io.containerd.grpc.v1.cri"']['sandbox_image'] = \
                f"{inventory['services']['kubeadm']['imageRepository']}/pause:{pause_version}"

    if inventory['services'].get('thirdparties', []) and thirdparties_address:
        for destination, config in inventory['services']['thirdparties'].items():

            if isinstance(config, str):
                new_source = inventory['services']['thirdparties'][destination]
            elif config.get('source') is not None:
                new_source = inventory['services']['thirdparties'][destination]['source']
            else:
                continue

            for binary in ['kubeadm', 'kubelet', 'kubectl']:
                if destination == '/usr/bin/' + binary:
                    new_source = new_source.replace('https://storage.googleapis.com/kubernetes-release/release',
                                                    '%s/kubernetes/%s'
                                                    % (thirdparties_address, binary))

            if '/usr/bin/calicoctl' == destination:
                new_source = new_source.replace('https://github.com/projectcalico/calico/releases/download',
                                                '%s/projectcalico/calico'
                                                % thirdparties_address)

            if '/usr/bin/crictl.tar.gz' == destination:
                new_source = new_source.replace('https://github.com/kubernetes-sigs/cri-tools/releases/download',
                                                '%s/kubernetes-sigs/cri-tools'
                                                % thirdparties_address)
            if isinstance(config, str):
                inventory['services']['thirdparties'][destination] = new_source
            else:
                inventory['services']['thirdparties'][destination]['source'] = new_source

    return inventory


def apply_registry_endpoints(inventory, cluster):

    if not inventory['registry'].get('mirror_registry'):
        inventory['registry']['mirror_registry'] = 'registry.cluster.local'

    registry_mirror_address = inventory['registry']['mirror_registry']

    # todo Currently registry.endpoints is used only for containerd registry mirrors, but it can be provided explicitly.
    #  Probably we could make endpoints optional in this case.
    containerd_endpoints = inventory['registry']['endpoints']
    thirdparties_address = inventory['registry'].get('thirdparties')

    return registry_mirror_address, containerd_endpoints, thirdparties_address


def append_controlplain(inventory, cluster: Optional[KubernetesCluster]):

    if inventory.get('control_plain', {}).get('internal') and inventory.get('control_plain', {}).get('external'):
        if cluster:
            cluster.log.verbose('Control plains are set manually, nothing to detect.')
        return inventory

    if cluster:
        cluster.log.verbose('Detecting control plains...')

    # calculate controlplain ips
    internal_address = None
    internal_address_source = None
    external_address = None
    external_address_source = None

    # vrrp_ip section is not enriched yet
    # todo what if ip is an ip of some node to remove?
    if inventory.get('vrrp_ips'):
        for i, item in enumerate(inventory['vrrp_ips']):
            if isinstance(item, str):
                if internal_address is None:
                    internal_address = item
                    internal_address_source = 'vrrp_ip[%s]' % i
            # todo remove p1_migrate_not_bind_vrrp_fix after next release
            elif item.get('params', {}).get('maintenance-type', False) != 'not bind' \
                    or (cluster and not cluster.context.get('p1_migrate_not_bind_vrrp_fix', True)):
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
        for role in ['balancer', 'master', 'control-plane']:
            # nodes are not compiled to groups yet
            for node in inventory['nodes']:
                if role in node['roles'] and 'remove_node' not in node['roles']:
                    if internal_address is None or node.get('control_endpoint', False):
                        internal_address = node['internal_address']
                        internal_address_source = role
                        if node.get('name'):
                            internal_address_source += ' \"%s\"' % node['name']
                    if node.get('address') and (external_address is None or node.get('control_endpoint', False)):
                        external_address = node['address']
                        external_address_source = role
                        if node.get('name'):
                            external_address_source += ' \"%s\"' % node['name']

    if external_address is None:
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


def recursive_apply_defaults(defaults, section):
    for key, value in defaults.items():
        if isinstance(value, dict) and section.get(key) is not None and section[key]:
            recursive_apply_defaults(value, section[key])
        # check if target section exists and not empty
        elif section.get(value) is not None and section[value]:

            if isinstance(section[value], list):
                for i, v in enumerate(section[value]):
                    # copy defaults as new dict, to avoid problems with memory links
                    node_config = deepcopy(section[key])

                    # update defaults with custom-defined node configs
                    # TODO: Use deepmerge instead of update
                    node_config.update(v)

                    # replace old node config with merged one
                    section[value][i] = node_config

            else:
                # deepcopy the whole section, otherwise it will break dict while replacing
                section_copy = deepcopy(section[value])
                for custom_key, custom_value in section_copy.items():
                    # here section['key'] refers to default, not custom value
                    default_value = deepcopy(section[key])
                    section[value][custom_key] = default_merger.merge(default_value, custom_value)


def calculate_node_names(inventory: dict, cluster):
    roles_iterators = {}
    for i, node in enumerate(inventory['nodes']):
        for role_name in ['control-plane', 'worker', 'balancer']:
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
                    inventory['nodes'][i]['name'] = '%s-%s' % (role_name, role_i)
    return inventory


def verify_node_names(inventory, cluster):
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


def calculate_nodegroups(inventory, cluster):
    for role in cluster.ips.keys():
        cluster.nodes[role] = cluster.make_group(cluster.ips[role])
    return inventory


def merge_defaults(inventory: dict, cluster: KubernetesCluster):
    base_inventory = deepcopy(static.DEFAULTS)

    inventory = default_merger.merge(base_inventory, inventory)
    # it is necessary to temporary put half-compiled inventory to cluster inventory field
    cluster._inventory = inventory
    return inventory


def enrich_inventory(cluster: KubernetesCluster, inventory: dict, make_dumps=True, enrichment_functions=None):
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


def compile_inventory(inventory, cluster):

    # convert references in yaml to normal values
    iterations = 100
    root = deepcopy(inventory)
    root['globals'] = static.GLOBALS

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


def compile_object(log, struct, root, ignore_jinja_escapes=True):
    if isinstance(struct, list):
        new_struct = []
        for i, v in enumerate(struct):
            struct[i] = compile_object(log, v, root, ignore_jinja_escapes=ignore_jinja_escapes)
            # delete empty list entries, which can appear after jinja compilation
            if struct[i] != '':
                new_struct.append(struct[i])
        struct = new_struct
    elif isinstance(struct, dict):
        for k, v in struct.items():
            struct[k] = compile_object(log, v, root, ignore_jinja_escapes=ignore_jinja_escapes)
    elif isinstance(struct, str) and ('{{' in struct or '{%' in struct):
        struct = compile_string(log, struct, root, ignore_jinja_escapes=ignore_jinja_escapes)
    return struct


def compile_string(log, struct, root, ignore_jinja_escapes=True):
    log.verbose("Rendering \"%s\"" % struct)

    if ignore_jinja_escapes:
        iterator = escaped_expression_regex.finditer(struct)
        struct = re.sub(escaped_expression_regex, '', struct)
        struct = jinja.new(log, root).from_string(struct).render(**root)

        for match in iterator:
            span = match.span()
            struct = struct[:span[0]] + match.group() + struct[span[0]:]
    else:
        struct = jinja.new(log, root).from_string(struct).render(**root)

    log.verbose("\tRendered as \"%s\"" % struct)
    return struct


def escape_jinja_characters_for_inventory(cluster: KubernetesCluster, obj):
    if isinstance(obj, dict):
        for key, value in obj.items():
            obj[key] = escape_jinja_characters_for_inventory(cluster, value)
    elif isinstance(obj, list):
        for key, value in enumerate(obj):
            obj[key] = escape_jinja_characters_for_inventory(cluster, value)
    elif isinstance(obj, str):
        obj = _escape_jinja_character(obj)
    return obj


def _escape_jinja_character(value):
    if '{{' in value and '}}' in value and re.search(jinja_query_regex, value):
        matches = re.findall(jinja_query_regex, value)
        for match in matches:
            # TODO: rewrite to correct way of match replacement: now it can cause "{raw}{raw}xxx.." circular bug
            value = value.replace(match, '{% raw %}'+match+'{% endraw %}')
    return value


def prepare_for_dump(inventory, copy=True):
    # preparation for dump required to remove memory links

    if copy:
        dump_inventory = deepcopy(inventory)
    else:
        dump_inventory = inventory

    for i, node in enumerate(dump_inventory['nodes']):
        if 'connection' in dump_inventory['nodes'][i]:
            del dump_inventory['nodes'][i]['connection']

    return dump_inventory


def manage_true_false_values(inventory, cluster):
    # Check undefined values for plugin.name.install and convert it to bool
    for plugin_name, plugin_item in inventory["plugins"].items():
        # Check install value
        if 'install' not in plugin_item:
            continue
        value = utils.true_or_false(plugin_item.get('install', False))
        if value == 'undefined':
            raise ValueError(f"Found unsupported value for plugin.{plugin_name}.install: {plugin_item['install']}")
        plugin_item['install'] = value == 'true'
    return inventory
