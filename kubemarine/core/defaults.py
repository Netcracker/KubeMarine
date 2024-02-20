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
from typing import Optional, Dict, Any, Tuple, List, Callable, Union

import yaml

from kubemarine.core.cluster import KubernetesCluster, EnrichmentStage, enrichment
from kubemarine.core.errors import KME
from kubemarine import jinja, keepalived, haproxy, controlplane, kubernetes, thirdparties
from kubemarine.core import utils, static, log, os
from kubemarine.core.yaml_merger import default_merger
from kubemarine.cri.containerd import contains_old_format_properties


supported_defaults = {
    'rbac': {
        'account_defaults': 'accounts'
    },
    'node_defaults': 'nodes',
}

invalid_node_name_regex = re.compile("[^a-z-.\\d]", re.M)
escaped_expression_regex = re.compile('({%[\\s*|]raw[\\s*|]%}.*?{%[\\s*|]endraw[\\s*|]%})', re.M)
jinja_query_regex = re.compile("{{ .* }}", re.M)


@enrichment(EnrichmentStage.LIGHT, procedures=['add_node'])
def add_node_enrich_roles(cluster: KubernetesCluster) -> None:
    # At LIGHT stage, we should mark the nodes with `add_node` service role to find them after compilation.
    # This is for optimization to avoid two-staged enrichment even for connections only.
    for node in cluster.procedure_inventory['nodes']:
        # deepcopy is necessary, otherwise role append will happen in procedure_inventory too
        node = utils.deepcopy_yaml(node)
        node["roles"].append("add_node")
        cluster.inventory["nodes"].append(node)


@enrichment(EnrichmentStage.LIGHT, procedures=['remove_node'])
def remove_node_enrich_roles(cluster: KubernetesCluster) -> None:
    # At LIGHT stage, we should mark the nodes with `remove_node` service role to find them after compilation.
    # This is for optimization to avoid two-staged enrichment even for connections only.
    node_names_to_remove = [node['name'] for node in cluster.procedure_inventory["nodes"]]
    for node_remove in node_names_to_remove:
        for node in cluster.inventory['nodes']:
            # Inventory is not compiled at this step.
            # Expecting that the names are not jinja, or the same jinja expressions.
            if node['name'] == node_remove:
                node['roles'].append('remove_node')
                break
        else:
            raise Exception(f"Failed to find node to remove {node_remove} among existing nodes")


@enrichment(EnrichmentStage.PROCEDURE, procedures=['add_node'])
def enrich_add_nodes(cluster: KubernetesCluster) -> None:
    # Unlike at LIGHT stage (add_node_enrich_roles), at PROCEDURE stage we add the nodes without service roles.
    for new_node in cluster.procedure_inventory["nodes"]:
        node = utils.deepcopy_yaml(new_node)
        cluster.inventory["nodes"].append(node)


@enrichment(EnrichmentStage.PROCEDURE, procedures=['remove_node'])
def enrich_remove_nodes(cluster: KubernetesCluster) -> None:
    # Unlike at LIGHT stage (remove_node_enrich_roles), at PROCEDURE stage we remove the nodes completely.
    node_names_to_remove = [node['name'] for node in cluster.procedure_inventory["nodes"]]
    for node_remove in node_names_to_remove:
        for i, node in enumerate(cluster.inventory['nodes']):
            if node['name'] == node_remove:
                del cluster.inventory['nodes'][i]
                break


@enrichment(EnrichmentStage.LIGHT, procedures=['add_node', 'remove_node'])
def remove_service_roles(cluster: KubernetesCluster) -> None:
    for node in cluster.inventory['nodes']:
        roles = node['roles']
        for role in ('add_node', 'remove_node'):
            if role in roles:
                roles.remove(role)


@enrichment(EnrichmentStage.ALL)
def apply_defaults(cluster: KubernetesCluster) -> None:
    recursive_apply_defaults(supported_defaults, cluster.inventory)


@enrichment(EnrichmentStage.ALL)
def calculate_connect_to(cluster: KubernetesCluster) -> None:
    for node in cluster.inventory["nodes"]:
        address = cluster.get_access_address_from_node(node)
        # we definitely know how to connect
        node["connect_to"] = address


@enrichment(EnrichmentStage.ALL)
def calculate_nodegroups(cluster: KubernetesCluster) -> None:
    for nodes, skip_role in (
            (cluster.previous_nodes, 'add_node'),
            (cluster.nodes, 'remove_node'),
    ):
        if nodes:
            # Since this is the first enrichment procedure that fills the nodes,
            # having non-empty nodes means they are externally provided (e.g. at PROCEDURE stage).
            continue

        ips: Dict[str, List[str]] = {
            "all": []
        }

        for node in cluster.inventory["nodes"]:
            if skip_role in node['roles']:
                continue

            address = node['connect_to']
            ips['all'].append(address)
            for role in node['roles']:
                if role not in ('remove_node', 'add_node'):
                    ips.setdefault(role, []).append(address)

        for role in ips.keys():
            nodes[role] = cluster.make_group(ips[role])


@enrichment(EnrichmentStage.FULL)
def apply_registry(cluster: KubernetesCluster) -> None:
    inventory = cluster.inventory

    if not inventory.get('registry'):
        cluster.log.verbose('Unified registry is not used')
        return

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
        if old_format_result:
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

    if thirdparties_address:
        for destination, config in inventory['services']['thirdparties'].items():
            if not thirdparties.is_default_thirdparty(destination) or isinstance(config, str) or 'source' in config:
                continue

            source, sha1 = thirdparties.get_default_thirdparty_identity(cluster.inventory, destination, in_public=False)
            source = source.format(registry=thirdparties_address)
            config['source'] = source
            if 'sha1' not in config:
                config['sha1'] = sha1


def apply_registry_endpoints(inventory: dict) -> Tuple[str, List[str], Optional[str]]:

    if not inventory['registry'].get('mirror_registry'):
        inventory['registry']['mirror_registry'] = 'registry.cluster.local'

    registry_mirror_address = inventory['registry']['mirror_registry']

    # todo Currently registry.endpoints is used only for containerd registry mirrors, but it can be provided explicitly.
    #  Probably we could make endpoints optional in this case.
    containerd_endpoints = inventory['registry']['endpoints']
    thirdparties_address = inventory['registry'].get('thirdparties')

    return registry_mirror_address, containerd_endpoints, thirdparties_address


@enrichment(EnrichmentStage.ALL)
def append_controlplain(cluster: KubernetesCluster) -> None:
    _append_controlplain(cluster.inventory, cluster.log)


def _append_controlplain(inventory: dict, logger: log.EnhancedLogger) -> None:

    if inventory.get('control_plain', {}).get('internal') and inventory.get('control_plain', {}).get('external'):
        logger.verbose('Control plains are set manually, nothing to detect.')

    logger.verbose('Detecting control plains...')

    # calculate controlplain ips
    internal_address: Optional[str] = None
    internal_address_source: Optional[str] = None
    external_address: Optional[str] = None
    external_address_source: Optional[str] = None

    balancer_names = keepalived.get_all_balancer_names(inventory)
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

    if internal_address is not None and external_address is None:
        logger.warning('VRRP_IPs has an internal address, but do not have an external one. Your configuration may be incorrect. Trying to handle this problem automatically...')

    if internal_address is None or external_address is None:
        # 'master' role is not deleted due to unit tests are not refactored
        for role in ['balancer', 'control-plane', 'master']:
            # nodes are not compiled to groups yet
            for node in inventory['nodes']:
                if role in node['roles']:
                    if internal_address is None or node.get('control_endpoint', False):
                        internal_address = node['internal_address']
                        internal_address_source = f"{role} \"{node['name']}\""
                    if node.get('address') and (external_address is None or node.get('control_endpoint', False)):
                        external_address = node['address']
                        external_address_source = f"{role} \"{node['name']}\""

    if external_address is None:
        logger.warning('Failed to detect external control plain. Something may work incorrect!')
        external_address = internal_address

    logger.debug('Control plains:\n   Internal: %s (%s)\n   External: %s (%s)' % (internal_address, internal_address_source, external_address, external_address_source))

    # apply controlplain ips
    if not inventory.get('control_plain'):
        inventory['control_plain'] = {}

    if not inventory['control_plain'].get('internal'):
        inventory['control_plain']['internal'] = internal_address

    if not inventory['control_plain'].get('external'):
        inventory['control_plain']['external'] = external_address


def recursive_apply_defaults(defaults: dict, section: dict) -> None:
    for key, value in defaults.items():
        if isinstance(value, dict) and section.get(key) is not None and section[key]:
            recursive_apply_defaults(value, section[key])
        # check if target section exists and not empty
        elif section.get(value) is not None:
            for i, custom_value in enumerate(section[value]):
                # copy defaults as new dict, to avoid problems with memory links
                default_value = utils.deepcopy_yaml(section[key])

                # update defaults with custom-defined node configs
                # TODO: Use deepmerge instead of update
                default_value.update(custom_value)

                # replace old node config with merged one
                section[value][i] = default_value


@enrichment(EnrichmentStage.ALL)
def calculate_node_names(cluster: KubernetesCluster) -> None:
    roles_iterators: Dict[str, int] = {}
    for i, node in enumerate(cluster.inventory['nodes']):
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


@enrichment(EnrichmentStage.ALL)
def verify_nodes(cluster: KubernetesCluster) -> None:
    known_names = []
    known_hosts = []
    known_internal_addresses = []
    for node in cluster.inventory['nodes']:
        node_name = node['name']
        if node_name in known_names:
            raise Exception('Node name %s is duplicated in configfile' % node_name)
        if re.findall(invalid_node_name_regex, node_name):
            raise Exception('Node name \"%s\" contains invalid characters. A DNS-1123 subdomain must consist of lower '
                            'case alphanumeric characters, \'-\' or \'.\'' % node_name)
        known_names.append(node_name)

        host = node['connect_to']
        if host in known_hosts:
            raise Exception('Access address %s is duplicated in configfile' % host)
        known_hosts.append(host)

        internal_address = node['internal_address']
        if internal_address in known_internal_addresses:
            raise Exception('Internal address %s is duplicated in configfile' % internal_address)
        known_internal_addresses.append(internal_address)

    known_gateway_node_names = []
    for gateway_node in cluster.inventory.get('gateway_nodes', []):
        node_name = gateway_node['name']
        if node_name in known_gateway_node_names:
            raise Exception(f"Gateway node name {node_name} is duplicated in configfile")

        known_gateway_node_names.append(node_name)


@enrichment(EnrichmentStage.ALL)
def merge_defaults(cluster: KubernetesCluster) -> dict:
    base_inventory = utils.deepcopy_yaml(static.DEFAULTS)
    inventory: dict = default_merger.merge(base_inventory, cluster.inventory)
    return inventory


@enrichment(EnrichmentStage.ALL)
def compile_inventory(cluster: KubernetesCluster) -> None:
    inventory = cluster.inventory
    # convert references in yaml to normal values
    iterations = 100
    root = utils.deepcopy_yaml(inventory)
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

    compile_object(cluster.log, inventory, root, ignore_jinja_escapes=False)
    dump_inventory(cluster, cluster.context, "cluster_precompiled.yaml")


def dump_inventory(cluster: KubernetesCluster, context: dict, filename: str) -> None:
    if not utils.is_dump_allowed(context, filename):
        return

    inventory = utils.deepcopy_yaml(cluster.inventory)
    inventory_for_dump = controlplane.controlplane_finalize_inventory(cluster, inventory)

    data = yaml.dump(inventory_for_dump)
    utils.dump_file(context, data, filename)


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
    elif isinstance(struct, str) and jinja.is_template(struct):
        struct = compile_string(logger, struct, root, ignore_jinja_escapes=ignore_jinja_escapes)

    return struct


def compile_string(logger: log.EnhancedLogger, struct: str, root: dict,
                   ignore_jinja_escapes: bool = True) -> str:
    logger.verbose("Rendering \"%s\"" % struct)

    def precompile(struct: str) -> str:
        return compile_string(logger, struct, root)

    if ignore_jinja_escapes:
        iterator = escaped_expression_regex.finditer(struct)
        struct = re.sub(escaped_expression_regex, '', struct)
        struct = jinja.new(logger, recursive_compiler=precompile, precompile_filters={
            'kubernetes_version': kubernetes.verify_allowed_version
        }).from_string(struct).render(**root)

        # TODO this does not work for {raw}{jinja}{raw}{jinja}
        for match in iterator:
            span = match.span()
            struct = struct[:span[0]] + match.group() + struct[span[0]:]
    else:
        struct = jinja.new(logger, recursive_compiler=precompile).from_string(struct).render(**root)

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


def _get_primitive_values_registry() -> List[Tuple[List[str], Callable[[Any], Any], bool]]:
    return [
        (['services', 'cri', 'containerdConfig',
          'plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runc.options',
          'SystemdCgroup'], utils.strtobool, False),
        (['services', 'modprobe', '*', '*'], str, True),
        # kernel parameters are actually not always represented as integers
        (['services', 'sysctl', '*'], utils.strtoint, True),
        (['plugins', '*', 'install'], utils.strtobool, False),
        (['plugins', 'calico', 'typha', 'enabled'], utils.strtobool, False),
        (['plugins', 'calico', 'typha', 'replicas'], utils.strtoint, False),
        (['plugins', 'nginx-ingress-controller', 'ports', '*', 'hostPort'], utils.strtoint, False),
    ]


@enrichment(EnrichmentStage.FULL)
def manage_primitive_values(cluster: KubernetesCluster) -> None:
    paths_func_strip = _get_primitive_values_registry()
    for search_path, func, strip in paths_func_strip:
        _convert_primitive_values(cluster.inventory, [], search_path, func, strip)


def finalize_primitive_values(cluster: KubernetesCluster, inventory: dict) -> dict:
    paths_func_strip = _get_primitive_values_registry()
    for search_path, _, strip in paths_func_strip:
        if not strip:
            continue
        _set_overridden_blank_primitive_values(cluster.raw_inventory, inventory, [], search_path)
    return inventory


def _convert_primitive_values(struct: Union[dict, list], path: List[Union[str, int]],
                              search_path: List[str], func: Callable[[Any], Any], strip: bool) -> None:
    depth = len(path)
    section = search_path[depth]
    if section == '*':
        if isinstance(struct, list):
            for i in reversed(range(len(struct))):
                _convert_primitive_value_section(struct, i, path, search_path, func, strip)

        elif isinstance(struct, dict):
            for k in list(struct):
                _convert_primitive_value_section(struct, k, path, search_path, func, strip)

    # Only dict is possible here as struct
    elif section in struct:
        _convert_primitive_value_section(struct, section, path, search_path, func, strip)


def _convert_primitive_value_section(struct: Union[dict, list], section: Union[str, int],
                                     path: List[Union[str, int]],
                                     search_path: List[str], func: Callable[[Any], Any], strip: bool) -> None:
    value = struct[section]  # type: ignore[index]
    path.append(section)
    depth = len(path)
    if depth < len(search_path):
        _convert_primitive_values(value, path, search_path, func, strip)
    else:
        if strip and isinstance(value, str):
            value = value.strip()
        if strip and value == '':
            del struct[section]  # type: ignore[arg-type]
        else:
            try:
                struct[section] = func(value)  # type: ignore[index]
            except ValueError as e:
                raise ValueError(f"{str(e)} in section [{']['.join(repr(p) for p in path)}]")

    path.pop()


def _set_overridden_blank_primitive_values(raw_struct: Union[dict, list], struct: Union[dict, list],
                                           path: List[Union[str, int]],
                                           search_path: List[str]) -> None:
    depth = len(path)
    section = search_path[depth]
    if section == '*':
        if isinstance(raw_struct, list):
            for i in reversed(range(len(raw_struct))):
                _set_overridden_blank_primitive_value_section(raw_struct, struct, i, path, search_path)

        elif isinstance(raw_struct, dict):
            for k in list(raw_struct):
                _set_overridden_blank_primitive_value_section(raw_struct, struct, k, path, search_path)

    # Only dict is possible here as raw_struct / struct
    elif section in raw_struct:
        _set_overridden_blank_primitive_value_section(raw_struct, struct, section, path, search_path)


def _set_overridden_blank_primitive_value_section(raw_struct: Union[dict, list], struct: Union[dict, list],
                                                  section: Union[str, int], path: List[Union[str, int]],
                                                  search_path: List[str]) -> None:
    raw_value = raw_struct[section]  # type: ignore[index]
    path.append(section)
    depth = len(path)
    if depth < len(search_path):
        # Items can be deleted only in leafs, so it is safe to get nested struct by key.
        # See _convert_primitive_value_section()
        value = struct[section]  # type: ignore[index]
        _set_overridden_blank_primitive_values(raw_value, value, path, search_path)
    elif isinstance(struct, dict) and section not in struct:
        # Leaves can be stripped and deleted during enrichment.
        # If they were redefined in raw inventory, we should return blank string in finalized inventory.
        # If finalized inventory is used as a source inventory, it will again redefine defaults with blank strings,
        # that will be again deleted.
        # See _convert_primitive_value_section()
        struct[section] = ''

    path.pop()
