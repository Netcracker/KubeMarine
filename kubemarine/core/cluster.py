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
import dataclasses
import functools
from copy import deepcopy
from enum import Flag, auto, IntFlag
from types import FunctionType
from typing import Dict, List, Union, Iterable, Tuple, Optional, Any, Callable, cast, Sequence, Protocol

from ordered_set import OrderedSet

from kubemarine.core import log  # pylint: disable=unused-import
from kubemarine.core import utils, static
from kubemarine.core.connections import ConnectionPool
from kubemarine.core.environment import Environment
from kubemarine.core.errors import KME0006
from kubemarine.core.group import NodeGroup, NodeConfig

_AnyConnectionTypes = Union[str, NodeGroup]


class EnrichmentStage(IntFlag):
    """
    The class acts both as a descriptor of a desirable state of the `KubernetesCluster` object,
    and as a selector of `@enrichment` functions.

    For each stage, the cluster is enriched from the beginning selecting suitable enrichment functions.

    To enrich the cluster at some stage, it must first be enriched at all the previous stages
    unless certain optimizations are applied.
    """

    LIGHT = auto()
    """
    The KubernetesCluster enriched at this stage can only be used to connect to nodes
    to fetch and store data not related to the inventory.
    
    For enrichment function, you rarely need this flag as the only selector,
    but likely need `EnrichmentStage.ALL` instead.
    
    Procedure inventory can be taken into account to enrich connections.
    """

    DEFAULT = auto()
    """
    The KubernetesCluster is enriched at this stage not taking into account the procedure inventory.
    After enrichment, the cluster and its enrichment products should be fully read-only.
    Only enriched inventory can be inspected in this state, but neither context, nor the procedure inventory.
    
    The KubernetesCluster object in this state can be used as backup before running of the `Action`.
    It can also be `evolved` to this state from PROCEDURE state.
    Either evolved (if necessary) or not, it can be used to dump the finalized inventory.
    
    For enrichment function, you never need this flag as the only selector.
    Use `EnrichmentStage.FULL` or other compound selectors.
    """

    PROCEDURE = auto()
    """
    The KubernetesCluster is finally enriched at this stage taking into account the procedure inventory.
    Execution on the cluster must be performed only in ths state.
    
    For enrichment function, you can use this flag as the only selector to only merge the procedure inventory,
    or to only verify the result of the merge.
    In this case, it is necessary to specify procedures for which the function is applicable.
    See also `@enrichment`.
    """

    # Some useful compound selectors of enrichment functions.
    FULL = DEFAULT | PROCEDURE
    ALL = LIGHT | DEFAULT | PROCEDURE
    NONE = 0
    """Special flag typically denoting that nothing is enriched."""

    __str__ = Flag.__str__

    @staticmethod
    def values() -> List['EnrichmentStage']:
        return list(EnrichmentStage)


class _Enrichment(Protocol):
    # The method intentionally lacks of `EnrichmentStage` argument for proper encapsulation
    def __call__(self, __cluster: 'KubernetesCluster') -> Optional[dict]: ...


class EnrichmentFunction(_Enrichment):
    """
    Wrapper around callable that performs enrichment with selectors.
    See `@enrichment`.
    """

    def __init__(self, delegate: _Enrichment, stages: EnrichmentStage, procedures: List[str] = None):
        if EnrichmentStage.DEFAULT in stages:
            if EnrichmentStage.PROCEDURE not in stages:
                raise ValueError("If enrichment function is applied at DEFAULT stage, "
                                 "it should also be applied at PROCEDURE stage")
            if procedures is not None:
                raise ValueError("Enrichment function can be restricted to some procedures "
                                 "only if it is applied at PROCEDURE and/or LIGHT stages")
        elif EnrichmentStage.PROCEDURE in stages and procedures is None:
            raise ValueError("If enrichment function is applied at PROCEDURE stage, but not at DEFAULT stage, "
                             "it should be restricted to some procedures")

        self.delegate = delegate
        self.stages = stages
        self.procedures: Optional[List[str]] = procedures

    # The method intentionally lacks of `EnrichmentStage` argument for proper encapsulation
    def __call__(self, cluster: 'KubernetesCluster') -> Optional[dict]:
        return self.delegate(cluster)

    @property
    def name(self) -> str:
        func = cast(FunctionType, self.delegate)
        return f"{func.__module__}.{func.__qualname__}"


def enrichment(stages: EnrichmentStage, procedures: List[str] = None) -> Callable[[_Enrichment], EnrichmentFunction]:
    """
    Wraps callable that performs enrichment, persisting selectors as the wrapper attributes.
    The selectors are supplied as the arguments of this decorator.

    :param stages: `EnrichmentStage` stages to run this function at.
    :param procedures: list of procedures for which the function is applicable.
    """
    def helper(fn: _Enrichment) -> EnrichmentFunction:
        wrapper = EnrichmentFunction(fn, stages, procedures)
        functools.update_wrapper(wrapper, fn)
        return wrapper

    return helper


@dataclasses.dataclass(repr=False)
class _EnrichmentProducts:
    """States of inventory and context at the particular `EnrichmentStage` of enrichment."""
    inventory: dict
    context: Optional[dict]
    procedure_inventory: Optional[dict]

    nodes_inventory: Dict[str, dict] = dataclasses.field(default_factory=dict)
    nodes: Dict[str, Dict[str, NodeGroup]] = dataclasses.field(default_factory=dict)

    formatted_inventory: Optional[dict] = None
    raw_inventory: Optional[dict] = None


class KubernetesCluster(Environment):

    def __init__(self, inventory: dict, context: dict, procedure_inventory: dict,
                 logger: log.EnhancedLogger,
                 connection_pool: ConnectionPool = None, nodes_context: Dict[str, Any] = None) -> None:
        # Enrichment stage field should not be opened even for read only aims.
        # Such encapsulation ensures that enrichment functions do not know about at what stage they are currently run.
        self._enrichment_stage = EnrichmentStage.NONE
        self._products = _EnrichmentProducts(
            utils.deepcopy_yaml(inventory), deepcopy(context), utils.deepcopy_yaml(procedure_inventory))
        self._previous_products = self._products
        self._products.nodes['nodes'] = self._products.nodes['previous'] = {}

        self._logger = logger

        self._connection_pool: Optional[ConnectionPool] = connection_pool
        self._nodes_context: Optional[Dict[str, Any]] = nodes_context

    def enrich(self, stage: EnrichmentStage,
               *,
               enrichment_fns: List[EnrichmentFunction],
               previous_cluster: Optional['KubernetesCluster']) -> 'KubernetesCluster':
        """
        Enrich the cluster to the state represented by the specified enrichment `stage`.

        :param stage: desirable state of the cluster object.
        :param enrichment_fns: enrichment functions to run.
        :param previous_cluster: cluster enriched at the previous stage.
        :return: this cluster object enriched at the specified stage.
        """
        if stage not in EnrichmentStage.values():
            raise ValueError(f"Target state should be one of ({', '.join(map(str, EnrichmentStage))}), got: {stage}")

        if self._enrichment_stage != EnrichmentStage.NONE:
            raise ValueError("The cluster is already enriched")

        # Flag.name is not None for not compound values in any Python version.
        self.log.verbose(f"Starting {cast(str, stage.name).lower()!r} enrichment")

        self._enrichment_stage = stage
        if stage == EnrichmentStage.DEFAULT:
            self._products.procedure_inventory = None
            args: dict = self.context['execution_arguments']
            args.pop('procedure_config', None)
        if stage == EnrichmentStage.PROCEDURE and previous_cluster is not None:
            self._previous_products = previous_cluster._products  # pylint: disable=protected-access

            # Previous nodes refer to previous cluster. Create new group to surely refer to this cluster.
            self._products.nodes['previous'] = {
                role: self.make_group(group.nodes)
                for role, group in self._previous_products.nodes['nodes'].items()}

        if stage == EnrichmentStage.LIGHT:
            # Need different instance of previous_nodes for LIGHT
            # because we should be able to distinguish initial and final nodes at this stage solely.
            # Still have the same instance of inventory holding all (added & removed) nodes.
            self._products.nodes['previous'] = {}

        # run required fields calculation
        for enrichment_fn in enrichment_fns:
            self.log.verbose(f'Calling fn "{enrichment_fn.name}"')
            inventory = enrichment_fn(self)

            if inventory is not None:
                self._products.inventory = inventory

        # For DEFAULT stage, KubernetesCluster.context should be available during enrichment,
        # but should not be accessed after it to exclude an opportunity of it being dependent on the inventory.
        # This is necessary for proper implementation of KubernetesCluster.evolve().
        if stage == EnrichmentStage.DEFAULT:
            self._products.context = None

        self.log.verbose('Enrichment finished!')

        return self

    @enrichment(EnrichmentStage.ALL)
    def convert_formatted_inventory(self) -> dict:
        products = self._products
        if self._enrichment_stage != EnrichmentStage.LIGHT:
            products.formatted_inventory = self.inventory

        products.raw_inventory = utils.convert_native_yaml(self.inventory)

        if self._enrichment_stage == EnrichmentStage.LIGHT:
            # inventory['nodes'] is already enriched, and the procedure inventory is no longer necessary.
            products.procedure_inventory = None
        elif self._enrichment_stage == EnrichmentStage.PROCEDURE:
            products.procedure_inventory = utils.convert_native_yaml(self.procedure_inventory)

        return utils.deepcopy_yaml(products.raw_inventory)

    @enrichment(EnrichmentStage.LIGHT)
    def init_nodes_context(self) -> None:
        self._connection_pool = self.create_connection_pool(self._get_all_nodes().get_hosts())
        self._nodes_context = {node['connect_to']: {} for node in self.inventory["nodes"]}

    def print_roles_summary(self) -> None:
        ips: Dict[str, OrderedSet[str]] = {}
        for nodes in (self.previous_nodes, self.nodes):
            for role, group in nodes.items():
                if role != 'all':
                    ips.setdefault(role, OrderedSet()).update(group.get_hosts())

        for role, group in (
                ('add_node', self.get_new_nodes()),
                ('remove_node', self.get_nodes_for_removal()),
        ):
            if not group.is_empty():
                ips[role] = OrderedSet(group.get_hosts())

        self.log.debug("Inventory file loaded:")
        for role, hosts in ips.items():
            self.log.debug("  %s %i" % (role, len(hosts)))
            for ip in hosts:
                self.log.debug("    %s" % ip)

    @property
    def previous_nodes(self) -> Dict[str, NodeGroup]:
        """
        Previous nodes of the cluster.
        For the cluster enriched at PROCEDURE stage, this includes nodes to be removed, but does not include added nodes.

        Should be changed only during the enrichment.
        """
        return self._products.nodes['previous']

    @property
    def nodes(self) -> Dict[str, NodeGroup]:
        """
        Final nodes of the cluster.
        For the cluster enriched at PROCEDURE stage, this includes added nodes, but does not include nodes to be removed.

        Should be changed only during the enrichment.
        """
        return self._products.nodes['nodes']

    @property
    def previous_inventory(self) -> dict:
        """
        The previous resulting inventory before procedure inventory is applied.
        For `install` and some other procedures this equals to the resulting `KubernetesCluster.inventory`.

        The property should be read only, and should be examined primarily at PROCEDURE stage or inside the flow.
        """
        return self._previous_products.inventory

    @property
    def inventory(self) -> dict:
        """
        The resulting inventory describing the cluster.

        Should be changed only during the enrichment.
        """
        return self._products.inventory

    @property
    def previous_nodes_inventory(self) -> Dict[str, dict]:
        """
        The previous resulting inventory describing specific nodes before procedure inventory is applied.
        For `install` and some other procedures this equals to the resulting `KubernetesCluster.nodes_inventory`.

        The inventory can be derived from the `KubernetesCluster.previous_inventory` only,
        and should not depend on other sources of information.

        The property should be read only, and should be examined primarily at PROCEDURE stage or inside the flow.
        """
        return self._previous_products.nodes_inventory

    @property
    def nodes_inventory(self) -> Dict[str, dict]:
        """
        The resulting inventory describing specific nodes.

        The inventory can be derived from the main `KubernetesCluster.inventory` only,
        and should not depend on other sources of information.

        Should be changed only during the enrichment.
        """
        return self._products.nodes_inventory

    @property
    def context(self) -> dict:
        """
        Context that stores an intermediate enrichment and execution result.

        At DEFAULT stage, the context is available only during enrichment.
        """
        context = self._products.context
        if context is None:
            raise ValueError("Context is not available after 'default' enrichment stage")

        return context

    @property
    def procedure_inventory(self) -> dict:
        procedure_inventory = self._products.procedure_inventory
        if procedure_inventory is None:
            raise ValueError("Procedure inventory is not available at 'default' or 'light' enrichment stage")

        return procedure_inventory

    @property
    def previous_raw_inventory(self) -> dict:
        """
        Inventory represented in python native objects before applying of any enrichment.

        The property should be read only.
        """
        raw_inventory = self._previous_products.raw_inventory
        if raw_inventory is None:
            raise ValueError("Enrichment is not yet started")

        return raw_inventory

    @property
    def raw_inventory(self) -> dict:
        """
        Inventory represented in python native objects after only procedure inventory is applied,
        but without applying of any other enrichment.

        The property should be read only.
        """
        raw_inventory = self._products.raw_inventory
        if raw_inventory is None:
            raise ValueError("Enrichment is not yet started")

        return raw_inventory

    @property
    def formatted_inventory(self) -> dict:
        """
        Formatted inventory after only procedure inventory is applied,
        but without applying of any other enrichment.

        The property can be examined after 'procedure' enrichment stage
        for maintenance procedures that have specific enrichment functions,
        and that support inventory recreation.

        The property should be read only.
        """
        formatted_inventory = self._products.formatted_inventory
        if formatted_inventory is None:
            raise ValueError("Formatted inventory is not available at 'light' enrichment stage")

        return formatted_inventory

    @property
    def nodes_context(self) -> Dict[str, Any]:
        """Various information about nodes that is not changed during Kubemarine run."""
        if self._nodes_context is None:
            raise ValueError("Nodes' context is available only after 'light' enrichment stage is finished")

        return self._nodes_context

    @property
    def connection_pool(self) -> ConnectionPool:
        if self._connection_pool is None:
            raise ValueError("Connection pool is available only after 'light' enrichment stage is finished")

        return self._connection_pool

    def create_connection_pool(self, hosts: List[str]) -> ConnectionPool:
        nodes = {}
        gateway_nodes = {}
        # iterate over inventory last because it redefines previous inventory
        for inventory in (self.previous_inventory, self.inventory):
            for node in inventory.get('nodes', []):
                nodes[node['connect_to']] = node

            for gateway_node in inventory.get('gateway_nodes', []):
                gateway_nodes[gateway_node['name']] = gateway_node

        return self._create_connection_pool(nodes, gateway_nodes, hosts)

    def _create_connection_pool(self, nodes: Dict[str, dict], gateway_nodes: Dict[str, dict], hosts: List[str]) -> ConnectionPool:
        return ConnectionPool(nodes, gateway_nodes, hosts)

    def _create_cluster_storage(self, context: dict) -> utils.ClusterStorage:
        return utils.ClusterStorage(self, context)

    @property
    def log(self) -> log.EnhancedLogger:
        return self._logger

    @property
    def globals(self) -> dict:
        return static.GLOBALS

    def make_group(self, ips: Iterable[_AnyConnectionTypes]) -> NodeGroup:
        return NodeGroup(ips, self)

    def get_access_address_from_node(self, node: NodeConfig) -> str:
        """
        Returns address which should be used to connect to the node via Fabric.
        The address also can be used as unique identifier of the node.
        """
        address: str
        if node.get('connect_to') is not None:
            address = node['connect_to']
        elif node.get('address') is not None:
            address = node['address']
        else:
            address = node['internal_address']

        return address

    def get_nodes_by_names(self, node_names: List[str]) -> List[NodeConfig]:
        result = []
        for node in self.inventory["nodes"]:
            if node['name'] in node_names:
                result.append(node)

        return result

    def get_node_by_name(self, node_name: str) -> Optional[NodeConfig]:
        nodes = self.get_nodes_by_names([node_name])
        return next(iter(nodes), None)

    def get_addresses_from_node_names(self, node_names: List[str]) -> List[str]:
        return [self.get_access_address_from_node(node)
                for node in self.get_nodes_by_names(node_names)]

    def get_node(self, host: _AnyConnectionTypes) -> NodeConfig:
        return self.make_group([host]).get_config()

    def get_node_name(self, host: _AnyConnectionTypes) -> str:
        name: str = self.get_node(host)['name']
        return name

    def make_group_from_nodes(self, node_names: List[str]) -> NodeGroup:
        ips = self.get_addresses_from_node_names(node_names)
        return self.make_group(ips)

    def make_group_from_roles(self, roles: Sequence[str]) -> NodeGroup:
        return self.nodes['all'].having_roles(roles)

    def get_new_nodes(self) -> NodeGroup:
        return self.nodes['all'].exclude_group(self.previous_nodes['all'])

    def get_new_nodes_or_self(self) -> NodeGroup:
        new_nodes = self.get_new_nodes()
        if not new_nodes.is_empty():
            return new_nodes
        return self.nodes['all']

    def get_nodes_for_removal(self) -> NodeGroup:
        return self.previous_nodes['all'].exclude_group(self.nodes['all'])

    def get_changed_nodes(self) -> NodeGroup:
        return self.get_new_nodes().include_group(self.get_nodes_for_removal())

    def get_unchanged_nodes(self) -> NodeGroup:
        return self._get_all_nodes().exclude_group(self.get_changed_nodes())

    def _get_all_nodes(self) -> NodeGroup:
        """Returns literally all nodes including added or removed"""
        return self.nodes['all'].include_group(self.previous_nodes['all'])

    def create_group_from_groups_nodes_names(self, groups_names: List[str], nodes_names: List[str]) -> NodeGroup:
        common_group = self.make_group_from_roles(groups_names)

        if nodes_names:
            common_group = common_group.include_group(self.make_group_from_nodes(nodes_names))

        return common_group

    def schedule_cumulative_point(self, point_method: Callable) -> None:
        self._check_within_flow()

        func = cast(FunctionType, point_method)
        point_fullname = func.__module__ + '.' + func.__qualname__

        if self.context['execution_arguments'].get('disable_cumulative_points', False):
            self.log.verbose('Method %s not scheduled - cumulative points disabled' % point_fullname)
            return

        if point_fullname in self.context['execution_arguments']['exclude_cumulative_points_methods']:
            self.log.verbose('Method %s not scheduled - it set to be excluded' % point_fullname)
            return

        scheduled_points = self.context.get('scheduled_cumulative_points', [])

        if point_method not in scheduled_points:
            scheduled_points.append(point_method)
            self.context['scheduled_cumulative_points'] = scheduled_points
            self.log.verbose('Method %s scheduled' % point_fullname)
        else:
            self.log.verbose('Method %s already scheduled' % point_fullname)

    def is_task_completed(self, task_path: str) -> bool:
        self._check_within_flow()
        return task_path in self.context['proceeded_tasks']

    def _check_within_flow(self, check: bool = True) -> None:
        if check != ('proceeded_tasks' in self.context):
            raise NotImplementedError(f"The method is called {'not ' if check else ''}within tasks flow execution")

    def check_nodes_accessibility(self, skip_check_iaas: bool = True) -> None:
        """Check nodes access statuses"""

        procedure: str = self.context['initial_procedure']
        if procedure == 'check_iaas' and skip_check_iaas:
            return
        
        if procedure == 'remove_node':
            group = self.make_group_from_roles(['control-plane', 'balancer'])
        else:
            group = self.make_group_from_roles(['control-plane', 'balancer']).include_group(self.get_new_nodes_or_self())

        # Check that nodes are online
        remained_offline = group.get_online_nodes(False)

        # Check that nodes are accessible.
        nodes = group.include_group(self.get_changed_nodes())
        inaccessible_online = nodes.get_online_nodes(True).exclude_group(nodes.get_accessible_nodes())

        if not remained_offline.is_empty() or not inaccessible_online.is_empty():
            raise KME0006(remained_offline.get_hosts(), inaccessible_online.get_hosts())

    def get_os_family_for_node(self, host: str) -> str:
        os_family: Optional[str] = self.nodes_context.get(host, {}).get('os', {}).get('family')
        if os_family is None:
            raise Exception('Node %s do not contain necessary context data' % host)
        return os_family

    def get_os_family_for_nodes(self, hosts: Iterable[str]) -> str:
        """
        Returns the detected operating system family for hosts.
        The method skips inaccessible nodes unless all nodes are inaccessible.

        :return: Detected OS family, possible values: "debian", "rhel", "rhel8", "rhel9",
                 "multiple", "unknown", "unsupported", "<undefined>".
        """
        os_families = {self.get_os_family_for_node(host) for host in hosts}
        if os_families == {'<undefined>'}:
            return '<undefined>'
        os_families.discard('<undefined>')

        if len(os_families) > 1:
            return 'multiple'
        elif len(os_families) == 0:
            raise Exception('Cannot get os family for empty nodes list')
        else:
            return list(os_families)[0]

    def get_os_family(self) -> str:
        """
        Returns common OS family name from all final remote hosts.
        The method skips inaccessible nodes unless all nodes are inaccessible.

        :return: Detected OS family, possible values: "debian", "rhel", "rhel8", "rhel9",
                 "multiple", "unknown", "unsupported", "<undefined>".
        """
        return self.nodes['all'].get_nodes_os()

    def get_os_identifiers(self) -> Dict[str, Tuple[str, str]]:
        """
        For each final and accessible node of the cluster, returns a tuple of OS (family, version).
        """
        os_ids = {}
        for host in self.nodes['all'].get_accessible_nodes().get_hosts():
            os_details = self.nodes_context[host]['os']
            os_ids[host] = (os_details['family'], os_details['version'])

        return os_ids

    def _get_associations(self, os_family: str) -> Dict[str, dict]:
        # Iterate over the resulting inventory first because it has priority.
        # Still need to check previous inventory if it contains OS specific section for nodes to be removed.
        for inventory in (self.inventory, self.previous_inventory):
            associations: Optional[dict] = (inventory.get('services', {}).get('packages', {})
                                            .get('associations', {}).get(os_family))
            if associations is not None:
                return associations

        raise Exception(f"Failed to get associations for {os_family!r} OS family")

    def get_associations(self) -> Dict[str, dict]:
        """
        Returns association for all packages from inventory for the cluster.
        The method can be used only if cluster has nodes with the same and supported OS family.
        """
        return self._get_associations(self.get_os_family())

    def _get_associations_for_os(self, os_family: str, package: str) -> dict:
        associations = self._get_associations(os_family).get(package)
        if associations is None:
            raise Exception(f'Failed to get associations for package "{package}"')

        return associations

    def get_associations_for_node(self, host: str, package: str) -> dict:
        """
        Returns all packages associations for specific node.

        :param host: The address of the node for which required to find the associations
        :param package: The package name to get the associations for
        :return: Dict with packages and their associations
        """
        node_os_family = self.get_os_family_for_node(host)
        return self._get_associations_for_os(node_os_family, package)

    def _get_package_associations_for_os(self, os_family: str, package: str, association_key: str) -> Any:
        associations = self._get_associations_for_os(os_family, package)
        association_value = associations.get(association_key)
        if association_value is None:
            raise Exception(f'Failed to get association "{association_key}" for package "{package}"')
        if not isinstance(association_value, str) and not isinstance(association_value, list):
            raise Exception(f'Unsupported association "{association_key}" value type for package "{package}", '
                            f'got: {str(association_value)}')

        return association_value

    def get_package_association(self, package: str, association_key: str) -> Any:
        """
        Returns the specified association for the specified package from inventory for the cluster.
        The method can be used only if cluster has nodes with the same and supported OS family.

        :param package: The package name to get the association for
        :param association_key: Association key to get
        :return: Association string or list value
        """
        os_family = self.get_os_family()
        return self._get_package_associations_for_os(os_family, package, association_key)

    def get_package_association_for_node(self, host: str, package: str, association_key: str) -> Any:
        """
        Returns the specified association for the specified package from inventory for specific node.

        :param host: The address of the node for which required to find the association
        :param package: The package name to get the association for
        :param association_key: Association key to get
        :return: Association string or list value
        """
        os_family = self.get_os_family_for_node(host)
        return self._get_package_associations_for_os(os_family, package, association_key)

    def evolve(self) -> 'KubernetesCluster':
        """
        If the cluster was enriched at PROCEDURE stage, make the cluster be enriched at DEFAULT stage.

        This allows to perform iterative changes in the inventory by sequentially applying the procedure enrichment.
        :return: this cluster object enriched at DEFAULT stage.
        """
        if self._enrichment_stage not in (EnrichmentStage.DEFAULT, EnrichmentStage.PROCEDURE):
            raise ValueError("Cluster instance can be evolved only if being in DEFAULT or PROCEDURE state")

        self._enrichment_stage = EnrichmentStage.DEFAULT
        self._products.context = None
        self._products.procedure_inventory = None
        self._previous_products = self._products

        return self

    def make_finalized_inventory(self, finalization_functions: List[Callable[['KubernetesCluster', dict], dict]]) \
            -> dict:
        prepared_inventory = utils.deepcopy_yaml(self.inventory)
        for finalize_fn in finalization_functions:
            prepared_inventory = finalize_fn(self, prepared_inventory)

        return prepared_inventory

    def preserve_inventory(self, context: dict, *, enriched: bool = True) -> None:
        self.log.debug("Start preserving of the information about the procedure.")
        cluster_storage = self._create_cluster_storage(context)
        cluster_storage.make_dir()
        if self.context.get('initial_procedure') == 'add_node':
            cluster_storage.upload_info_new_control_planes()
        cluster_storage.collect_procedure_info()
        cluster_storage.compress_archive(enriched)
        cluster_storage.upload_and_rotate()
