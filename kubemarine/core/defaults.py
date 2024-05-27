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
import json
import re
from typing import Optional, Dict, Any, Tuple, List, Callable, Union, Sequence, cast, Type

import yaml

from kubemarine.core.cluster import KubernetesCluster, EnrichmentStage, enrichment
from kubemarine import jinja, keepalived, haproxy, kubernetes, thirdparties
from kubemarine.core import utils, static, log, os
from kubemarine.core.proxytypes import Primitive, Index, Node
from kubemarine.core.yaml_merger import default_merger
from kubemarine.cri.containerd import contains_old_format_properties


supported_connection_defaults = {
    'node_defaults': 'nodes',
}

supported_defaults = {
    'rbac': {
        'account_defaults': 'accounts'
    },
}

connection_sections = [
    'nodes', 'node_defaults', 'gateway_nodes',
    'procedure_history',  # Required to preserve inventory
    'values', 'cluster_name'  # May be referred to in jinja expressions
]

ssh_access_default_properties = [
    'keyfile', 'password', 'username', 'connection_port', 'connection_timeout', 'gateway',
    'boot'  # Participates in workarounds and reboot. This dependency can potentially be avoided
]

ssh_access_node_properties = ssh_access_default_properties + [
    'address', 'internal_address', 'connect_to',
    'name',  # In context of connections, the name is used only in logging. This dependency can potentially be avoided.
    'roles'  # Required to distinguish control planes to preserve inventory.
]


invalid_node_name_regex = re.compile("[^a-z-.\\d]", re.M)


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
def apply_connection_defaults(cluster: KubernetesCluster) -> None:
    recursive_apply_defaults(supported_connection_defaults, cluster.inventory)


@enrichment(EnrichmentStage.FULL)
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

        for role, hosts in ips.items():
            nodes[role] = cluster.make_group(hosts)


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


@enrichment(EnrichmentStage.FULL)
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
        logger.warning('VRRP_IPs has an internal address, but do not have an external one. '
                       'Your configuration may be incorrect. Trying to handle this problem automatically...')

    if internal_address is None or external_address is None:
        for role in ['balancer', 'control-plane']:
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

    logger.debug('Control plains:\n   Internal: %s (%s)\n   External: %s (%s)'
                 % (internal_address, internal_address_source, external_address, external_address_source))

    # apply controlplain ips
    if not inventory.get('control_plain'):
        inventory['control_plain'] = {}

    if not inventory['control_plain'].get('internal'):
        inventory['control_plain']['internal'] = internal_address

    if not inventory['control_plain'].get('external'):
        inventory['control_plain']['external'] = external_address


def recursive_apply_defaults(defaults: dict, section: dict) -> None:
    for key, value in defaults.items():
        if isinstance(value, dict):
            if section.get(key) is not None and section[key]:
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
    for node in cluster.inventory['nodes']:
        # 'master' role is not deleted because calculate_node_names() can be run over old inventory,
        # that may still have the old role (LIGHT enrichment).
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


def restrict_connection_sections(inventory: dict) -> dict:
    """
    Returns shallow copy of the inventory with only those sections
    that participate in the enrichment of connections.
    """
    inventory = utils.subdict_yaml(inventory, connection_sections)
    node_defaults = inventory.get('node_defaults', {})
    if node_defaults:
        inventory['node_defaults'] = utils.subdict_yaml(node_defaults, ssh_access_default_properties)

    nodes = inventory.get('nodes', [])
    if nodes:
        inventory['nodes'] = nodes = list(nodes)
        for i, node in enumerate(nodes):
            nodes[i] = utils.subdict_yaml(node, ssh_access_node_properties)

    return inventory


@enrichment(EnrichmentStage.LIGHT)
def restrict_connections(cluster: KubernetesCluster) -> dict:
    return restrict_connection_sections(cluster.inventory)


@enrichment(EnrichmentStage.LIGHT)
def merge_connection_defaults(cluster: KubernetesCluster) -> dict:
    connection_defaults = restrict_connection_sections(static.DEFAULTS)
    return _merge_inventory(cluster, connection_defaults)


@enrichment(EnrichmentStage.FULL)
def merge_defaults(cluster: KubernetesCluster) -> dict:
    return _merge_inventory(cluster, static.DEFAULTS)


def _merge_inventory(cluster: KubernetesCluster, base: dict) -> dict:
    base_inventory = utils.deepcopy_yaml(base)
    inventory: dict = default_merger.merge(base_inventory, cluster.inventory)
    return inventory


@enrichment(EnrichmentStage.LIGHT)
def compile_connections(cluster: KubernetesCluster) -> None:
    return _compile_inventory(cluster, light=True)


@enrichment(EnrichmentStage.FULL)
def compile_inventory(cluster: KubernetesCluster) -> None:
    return _compile_inventory(cluster, light=False)


def _compile_inventory(cluster: KubernetesCluster, *, light: bool) -> None:
    inventory = cluster.inventory

    extra: Dict[str, Any] = {'env': os.Environ()}
    if not light:
        extra['globals'] = static.GLOBALS

    if light:
        # Management of primitive values is currently not necessary for LIGHT stage.
        env = Environment(cluster.log, inventory, recursive_compile=True, recursive_extra=extra)
        jinja.compile_node(inventory, [], env)
    else:
        primitives_config = _get_primitive_values_registry()
        env = Environment(cluster.log, inventory, recursive_compile=True, recursive_extra=extra,
                          primitives_config=primitives_config)
        compile_node_with_primitives(inventory, [], env, primitives_config)

    remove_empty_items(inventory)

    dump_inventory(cluster, cluster.context, "cluster_precompiled.yaml")


def dump_inventory(cluster: KubernetesCluster, context: dict, filename: str) -> None:
    if not utils.is_dump_allowed(context, filename):
        return

    data = yaml.dump(cluster.inventory)
    utils.dump_file(context, data, filename)


PrimitivesConfig = List[Tuple[List[str], Callable[[Any], Any]]]


def compile_node_with_primitives(struct: Union[list, dict],
                                 path: List[Union[str, int]],
                                 env: jinja.Environment,
                                 primitives_config: PrimitivesConfig) -> Union[list, dict]:
    if isinstance(struct, list):
        for i, v in enumerate(struct):
            struct[i] = compile_object_with_primitives(v, path, i, env, primitives_config)
    else:
        for k, v in struct.items():
            struct[k] = compile_object_with_primitives(v, path, k, env, primitives_config)

    return struct


def compile_object_with_primitives(struct: Union[Primitive, list, dict],
                                   path: List[Index], index: Index,
                                   env: jinja.Environment,
                                   primitives_config: PrimitivesConfig) -> Union[Primitive, list, dict]:
    depth = len(path)
    primitives_config = choose_nested_primitives_config(primitives_config, depth, index)

    path.append(index)
    if isinstance(struct, (list, dict)):
        if primitives_config:
            struct = compile_node_with_primitives(struct, path, env, primitives_config)
        else:
            struct = jinja.compile_node(struct, path, env)
    else:
        if isinstance(struct, str) and jinja.is_template(struct):
            struct = env.compile_string(struct, jinja.Path(path))

        struct = convert_primitive(struct, path, primitives_config)

    path.pop()
    return struct


def remove_empty_items(struct: Any) -> Any:
    if isinstance(struct, list):
        new_struct = []
        for v in struct:
            v = remove_empty_items(v)
            # delete empty list entries, which can appear after jinja compilation
            if v != '':
                new_struct.append(v)
        struct = new_struct
    elif isinstance(struct, dict):
        for k, v in struct.items():
            struct[k] = remove_empty_items(v)

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
    if jinja.is_template(value):
        value = '{{ %s }}' % (json.JSONEncoder().encode(value),)

    return value


def _get_primitive_values_registry() -> PrimitivesConfig:
    return [
        (['services', 'cri', 'containerdConfig',
          'plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runc.options',
          'SystemdCgroup'], utils.strtobool),
        (['services', 'modprobe', '*', '*', 'install'], utils.strtobool),
        # kernel parameters are actually not always represented as integers
        (['services', 'sysctl', '*', 'value'], utils.strtoint),
        (['services', 'sysctl', '*', 'install'], utils.strtobool),
        # kernel parameters are actually not always represented as integers
        (['patches', '*', 'services', 'sysctl', '*', 'value'], utils.strtoint),
        (['patches', '*', 'services', 'sysctl', '*', 'install'], utils.strtobool),
        (['plugins', '*', 'install'], utils.strtobool),
        (['plugins', 'calico', 'typha', 'enabled'], utils.strtobool),
        (['plugins', 'calico', 'typha', 'replicas'], utils.strtoint),
        (['plugins', 'nginx-ingress-controller', 'ports', '*', 'hostPort'], utils.strtoint),
    ]


def choose_nested_primitives_config(primitives_config: PrimitivesConfig, depth: int, index: Index) -> PrimitivesConfig:
    nested_config = []
    for search in primitives_config:
        search_path = search[0]
        if depth == len(search_path):
            continue

        section = search_path[depth]
        if section in ('*', index):
            nested_config.append(search)

    return nested_config


def convert_primitive(struct: Primitive, path: Sequence[Index], primitives_config: PrimitivesConfig) -> Primitive:
    for search_path, func in primitives_config:
        if len(search_path) == len(path):
            try:
                struct = func(struct)
            except ValueError as e:
                raise ValueError(f"{str(e)} in section {utils.pretty_path(path)}") from None

    return struct


class NodePrimitives(jinja.JinjaNode):
    """
    A Node that both compiles template strings and converts primitive values in the underlying `dict` or `list`.
    """

    def __init__(self, delegate: Union[dict, list], *,
                 path: jinja.Path, env: jinja.Environment,
                 primitives_config: PrimitivesConfig):
        super().__init__(delegate, path=path, env=env)
        self.primitives_config = primitives_config

    def _child(self, index: Index, val: Union[list, dict]) -> jinja.Node:
        primitives_config = self._nested_primitives_config(index)
        return self._child_type(index)(val, path=self.path + (index,), env=self.env,
                                       primitives_config=primitives_config)

    def _child_type(self, _: Index) -> Type['NodePrimitives']:
        return NodePrimitives

    def _convert(self, index: Index, val: Primitive) -> Primitive:
        val = super()._convert(index, val)

        primitives_config = self._nested_primitives_config(index)
        val = convert_primitive(val, self.path + (index,), primitives_config)

        return val

    def _nested_primitives_config(self, index: Index) -> PrimitivesConfig:
        depth = len(self.path)
        return choose_nested_primitives_config(self.primitives_config, depth, index)


class NodesCustomization:
    """
    Customize access to the particular sections of the inventory.
    """

    # pylint: disable=no-self-argument

    def __init__(nodes) -> None:
        # The classes below should customize access to the sections of the inventory,
        # while preserving the global behaviour of Node implementations: NodePrimitives, JinjaNode, Node.

        class Kubeadm(Node):
            def descend(self, index: Index) -> Union[Primitive, Node]:
                child: Union[Primitive, Node] = super().descend(index)

                if index == 'kubernetesVersion':
                    kubernetes.verify_allowed_version(cast(str, child))

                return child

        class Services(Node):
            def _child_type(self, index: Index) -> Type[Node]:
                if index == 'kubeadm':
                    return nodes.Kubeadm

                return super()._child_type(index)

        class Root(Node):
            def _child_type(self, index: Index) -> Type[Node]:
                if index == 'services':
                    return nodes.Services

                return super()._child_type(index)

        nodes.Kubeadm: Type[Node] = Kubeadm
        nodes.Services: Type[Node] = Services
        nodes.Root: Type[Node] = Root

    def derive(nodes, Base: Type[Node], delegate: dict, **kwargs: Any) -> Node:
        nodes.Kubeadm = cast(Type[Node], type("Kubeadm", (nodes.Kubeadm, Base), {}))
        nodes.Services = cast(Type[Node], type("Services", (nodes.Services, Base), {}))
        nodes.Root = cast(Type[Node], type("Root", (nodes.Root, Base), {}))

        return nodes.Root(delegate, **kwargs)


class Environment(jinja.Environment):
    """
    Environment that supports recursive compilation and on-the-fly conversion of primitive values.

    It also customizes access to the particular sections of the inventory.
    """

    def __init__(self, logger: log.EnhancedLogger, recursive_values: dict,
                 *,
                 recursive_compile: bool = False,
                 recursive_extra: Dict[str, Any] = None,
                 primitives_config: PrimitivesConfig = None):
        """
        Instantiate new environment and set default filters.

        :param logger: EnhancedLogger
        :param recursive_values: The render values access to which should be customized.
                                 They may also be automatically converted and compiled if necessary.
        :param recursive_compile: Flag that enables recursive compilation.
        :param recursive_extra: If recursive compilation occurs, these render values are supplied to the template.
        :param primitives_config: List of sections and convertors of primitive values.
        """
        self.recursive_compile = recursive_compile
        self.primitives_config = primitives_config
        super().__init__(logger, recursive_values, recursive_extra=recursive_extra)

    def create_root(self, delegate: dict) -> Node:
        kwargs = {}
        Base: Type[Node]
        if not self.recursive_compile:
            Base = Node
        else:
            Base = jinja.JinjaNode
            kwargs = {"path": jinja.Path(), "env": self}
            if self.primitives_config is not None:
                Base = NodePrimitives
                kwargs = {**kwargs, "primitives_config": self.primitives_config}

        return NodesCustomization().derive(Base, delegate, **kwargs)
