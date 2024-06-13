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
import shutil
from contextlib import contextmanager
from copy import deepcopy
from typing import Optional, Iterator, List, Dict, Any, Callable, cast

import yaml
import ruamel.yaml

import kubemarine.admission
import kubemarine.audit
import kubemarine.core.cluster
import kubemarine.core.defaults
import kubemarine.core.inventory
import kubemarine.core.schema
import kubemarine.cri
import kubemarine.cri.containerd
import kubemarine.haproxy
import kubemarine.k8s_certs
import kubemarine.keepalived
import kubemarine.kubernetes
import kubemarine.kubernetes_accounts
import kubemarine.modprobe
import kubemarine.packages
import kubemarine.plugins
import kubemarine.plugins.builtin
import kubemarine.plugins.calico
import kubemarine.plugins.kubernetes_dashboard
import kubemarine.plugins.local_path_provisioner
import kubemarine.plugins.nginx_ingress
import kubemarine.sysctl
import kubemarine.system
import kubemarine.thirdparties

from kubemarine.core import cluster as c  # pylint: disable=reimported
from kubemarine.core import utils, log, errors, static
from kubemarine.core.connections import ConnectionPool
from kubemarine.core.yaml_merger import default_merger


class DynamicResources:
    def __init__(self, context: dict) -> None:
        self.context = context
        """
        Context holding execution arguments and other auxiliary parameters which manage the execution flow.
        The context can be mutable, but only from action to action.
        If the changes are aimed to change the enrichment process, one should call `DynamicResources.reset_cluster()`.
        """
        self.result_context: dict = {}
        """
        Context that holds the aggregated result of the execution through the sequence of actions.
        """

        self._logger: Optional[log.EnhancedLogger] = None
        self._inventory: Optional[dict] = None
        self._procedure_inventory: Optional[dict] = None

        self._connection_pool: Optional[ConnectionPool] = None
        self._nodes_context: Optional[Dict[str, Any]] = None
        """
        The nodes_context variable should hold node specific information that is not changed during Kubemarine run.
        """

        self._skip_default_enrichment: Optional[bool] = None
        self._clusters: Dict[c.EnrichmentStage, c.KubernetesCluster] = {}

        args: dict = context['execution_arguments']
        self.inventory_filepath: Optional[str] = args['config']
        self.procedure_inventory_filepath: Optional[str] = args.get('procedure_config')

    def logger_if_initialized(self) -> Optional[log.EnhancedLogger]:
        return self._logger

    def logger(self) -> log.EnhancedLogger:
        if self._logger is None:
            self._logger = self._create_logger()

        return self._logger

    def inventory(self) -> dict:
        """
        Returns not enriched inventory with preserved comments/quotes.

        This inventory should be passed to the cluster instance.

        It can be used directly in the following scenarios:

        - To check the user-supplied sections and values before running of the enrichment.
          **Note:** This inventory is not compiled, so its values should be checked with care.
          In most cases it is safe to only check if the value is present or absent.

        - To change inventory inside patches.
          **Note:** Once the main `cluster()` is initialized (e.g. in some `RegularPatch`)
          It should be `DynamicResources.reset_cluster()` for the changes to take effect.

        :return: not enriched inventory with preserved comments/quotes
        """
        if self._inventory is None:
            self._inventory = self._load_inventory()

        return self._inventory

    def procedure_inventory(self) -> dict:
        """
        :return: parsed procedure inventory that is **not yet** validated by JSON schema
        """
        if self._procedure_inventory is None:
            if self.procedure_inventory_filepath:
                try:
                    with utils.open_external(self.procedure_inventory_filepath) as stream:
                        self._procedure_inventory = utils.yaml_structure_preserver().load(stream)
                except ruamel.yaml.YAMLError as exc:
                    utils.do_fail("Failed to load procedure inventory file", exc, logger=self._logger)

            if not self._procedure_inventory:
                self._procedure_inventory = {}

        return self._procedure_inventory

    def _load_inventory(self) -> dict:
        if not self.inventory_filepath:
            raise Exception("Path to inventory is not defined")
        logger = self._logger
        msg = "Loading inventory file '%s'" % self.inventory_filepath
        if logger is None:
            if not self.context['load_inventory_silent']:
                print(msg)  # pylint: disable=bad-builtin
        else:
            logger.info(msg)
        try:
            with utils.open_external(self.inventory_filepath) as stream:
                # load inventory as ruamel.yaml to save original structure
                inventory: dict = utils.yaml_structure_preserver().load(stream)

            return inventory
        except ruamel.yaml.YAMLError as exc:
            utils.do_fail("Failed to load inventory file", exc, logger=logger)

    def recreate_inventory(self) -> None:
        """
        Recreate initial inventory file using KubernetesCluster.formatted_inventory if the cluster is initialized,
        or this `inventory()` otherwise.
        Also, reset all dependent resources.

        Avoid using it directly, because previous inventory will be lost,
        and post-processing of actions may work incorrectly.
        """
        cluster = self.cluster_if_initialized()
        if cluster is not None:
            # The new inventory of DynamicResources should be taken from `formatted_inventory` of the cluster object.
            # Also, move enriched inventories from PROCEDURE to DEFAULT stage.
            self._inventory = utils.deepcopy_yaml(cluster.formatted_inventory)
            self.reset_cluster(c.EnrichmentStage.DEFAULT)

            self._clusters[self._get_effective_stage(c.EnrichmentStage.DEFAULT)] = cluster.evolve()

        self._store_inventory(self.inventory())

        # Do not clear _connection_pool to hold only one connection instance per each node.
        # No need to clear _nodes_context as it should not change during Kubemarine run.

    def _store_inventory(self, inventory: dict) -> None:
        if not self.inventory_filepath:
            raise Exception("Path to inventory is not defined")
        # replace initial inventory file with changed inventory
        buf = io.StringIO()
        utils.yaml_structure_preserver().dump(inventory, buf)
        utils.dump_file(self.context, buf.getvalue(), self.inventory_filepath, dump_location=False)

    def cluster_if_initialized(self) -> Optional[c.KubernetesCluster]:
        """
        :return: cluster instance if it was initialized at PROCEDURE or DEFAULT stage.
        """
        for stage in (c.EnrichmentStage.PROCEDURE, c.EnrichmentStage.DEFAULT):
            if stage in self._clusters:
                return self._clusters[stage]

        return None

    def cluster(self, stage: c.EnrichmentStage = c.EnrichmentStage.PROCEDURE) -> c.KubernetesCluster:
        """
        Returns already initialized cluster object or initializes a new cluster object.
        The returned cluster object is fully enriched unless different `enrichment_stage` is provided.

        For different enrichment stages different cluster instances are initialized.
        Before initializing and enriching the cluster at some stage,
        intermediate cluster instances are initialized and enriched at all the previous stages
        selecting suitable enrichment functions.

        Intermediate DEFAULT stage of enrichment can be skipped if it has the same functions as for PROCEDURE stage.
        In this case, the cluster for it will be the same as for PROCEDURE stage.

        :param stage: target enrichment stage of the cluster object.
        :return: `KubernetesCluster` object
        """
        if stage not in c.EnrichmentStage.values():
            raise ValueError(f"Cluster state should be one of ({', '.join(map(str, c.EnrichmentStage))}), "
                             f"got: {stage}")

        for new_stage in c.EnrichmentStage.values():
            if new_stage > stage:
                break

            new_stage = self._get_effective_stage(new_stage)
            if new_stage in self._clusters:
                continue

            ansible_inventory = (self.context['execution_arguments'].get('ansible_inventory_location')
                                 if new_stage == c.EnrichmentStage.PROCEDURE else None)

            self._clusters[new_stage] = cluster = self._create_cluster(
                self.context, new_stage,
                dump_inventory=True,
                print_roles_summary=(new_stage == c.EnrichmentStage.PROCEDURE),
                ansible_inventory=ansible_inventory
            )

            # Optimization: cache properties that are not changed during Kubemarine run.
            # These properties are passed to each new Kubernetes cluster object,
            # See also _new_cluster_instance() and KubernetesCluster.enrich()
            self._connection_pool = cluster.connection_pool
            self._nodes_context = cluster.nodes_context

        return self._clusters[self._get_effective_stage(stage)]

    def create_deviated_cluster(self, deviated_context: dict) -> c.KubernetesCluster:
        """
        Create new cluster instance with specified deviation of context params.
        The method work should minimize work with network and avoid RW work with filesystem.
        The cluster instance should be useful to develop a patch in case enrichment procedure is changed,
        and it is necessary to compare the result of old and new algorithm of enrichment.
        It should not be used in tasks.

        :param deviated_context dictionary to override context params.
        """
        sample_context = deepcopy(self.context)
        default_merger.merge(sample_context, deviated_context)
        sample_context['preserve_inventory'] = False
        args = sample_context['execution_arguments']
        args['disable_dump'] = True

        # Trigger initialization of LIGHT cluster if it is not done yet.
        # Nodes' context and connection pool of it will be transferred to the new deviated cluster.
        self.cluster(c.EnrichmentStage.LIGHT)
        # Use DEFAULT stage as we are not interested in applying of procedure inventory.
        # Difference in the enrichment should be driven by the deviated context.
        return self._create_cluster(sample_context, c.EnrichmentStage.DEFAULT,
                                    dump_inventory=False,
                                    print_roles_summary=True)

    def reset_cluster(self, stage: c.EnrichmentStage) -> None:
        """
        Reset clusters enriched at all stages higher than the specified stage.
        This ensures that new cluster instances will be initialized
        using `DynamicResources.context` and `DynamicResources.inventory()`.

        It is currently possible to reset to DEFAULT state only.

        :param stage: state to reset the cluster to
        """
        if stage != c.EnrichmentStage.DEFAULT:
            raise ValueError("Reset is currently supported only to DEFAULT enrichment state")

        stage = self._get_effective_stage(c.EnrichmentStage.DEFAULT)
        if stage not in self._clusters:
            # External changes of .context or .inventory() are aimed to vary the enrichment
            # affecting PROCEDURE stage only.
            # The cluster should be already enriched at DEFAULT stage to avoid unintended impact on it.
            raise ValueError(f"Cluster is not initialized at {stage.name!r} stage yet")

        self._clusters.pop(c.EnrichmentStage.PROCEDURE, None)

    def dump_finalized_inventory(self, cluster: c.KubernetesCluster) -> None:
        finalized_filename = "cluster_finalized.yaml"
        if not self.context['make_finalized_inventory']:
            return

        finalized_inventory = self.make_finalized_inventory(cluster)
        self._store_finalized_inventory(finalized_inventory, finalized_filename)

    def make_finalized_inventory(self, cluster: c.KubernetesCluster) -> dict:
        return cluster.make_finalized_inventory(self.finalization_functions())

    def _store_finalized_inventory(self, finalized_inventory: dict, finalized_filename: str) -> None:
        data = yaml.dump(finalized_inventory)
        utils.dump_file(self.context, data, finalized_filename)
        utils.dump_file(self.context, data, finalized_filename, dump_location=False)

    def collect_action_result(self) -> None:
        cluster = self._clusters.get(c.EnrichmentStage.PROCEDURE)
        if cluster is None:
            return

        procedure_context = {k: cluster.context[k]
                             for k in self.context['result']
                             if k in cluster.context}
        default_merger.merge(self.result_context, procedure_context)

    @contextmanager
    def _handle_enrichment_error(self) -> Iterator[None]:
        try:
            yield
        except errors.FailException:
            raise
        except (Exception, KeyboardInterrupt) as exc:
            raise errors.FailException("Failed to proceed inventory file", exc)

    def _create_cluster(self, context: dict, stage: c.EnrichmentStage,
                        *,
                        dump_inventory: bool,
                        print_roles_summary: bool,
                        ansible_inventory: Optional[str] = None) -> c.KubernetesCluster:
        with self._handle_enrichment_error():
            cluster = self._new_cluster_instance(context)
            previous_cluster = (self._clusters.get(c.EnrichmentStage.DEFAULT)
                                if stage == c.EnrichmentStage.PROCEDURE
                                else None)

            cluster.enrich(stage, enrichment_fns=self._choose_enrichment_functions(stage),
                           previous_cluster=previous_cluster)

            if stage != c.EnrichmentStage.DEFAULT and 'dump_subdir' in cluster.context:
                self.context['dump_subdir'] = cluster.context['dump_subdir']

            if dump_inventory:
                self._dump_inventory(cluster, stage)

            if print_roles_summary:
                cluster.print_roles_summary()

            if ansible_inventory is not None:
                utils.make_ansible_inventory(ansible_inventory, cluster)

        return cluster

    def _dump_inventory(self, cluster: c.KubernetesCluster, stage: c.EnrichmentStage) -> None:
        # Flag.name is not None for not compound values in any Python version.
        suffix = cast(str, stage.name).lower()
        filename = f'cluster_{suffix}.yaml'
        context = self.context

        kubemarine.core.defaults.dump_inventory(cluster, context, filename)

        if stage == c.EnrichmentStage.PROCEDURE and utils.is_dump_allowed(context, 'cluster.yaml'):
            # Although cluster_procedure.yaml can be used for debug aims, previously it was cluster.yaml.
            # Since cluster_procedure.yaml is not always dumped in comparison to cluster.yaml (--disable-dump),
            # let's dump cluster.yaml for backward compatibility.
            #
            # cluster.yaml also participates in the inventory preservation and may differ from cluster_procedure.yaml
            # See flow._post_process_actions_group()
            if utils.is_dump_allowed(context, filename):
                shutil.copyfile(utils.get_dump_filepath(context, filename),
                                utils.get_dump_filepath(context, 'cluster.yaml'))
            else:
                kubemarine.core.defaults.dump_inventory(cluster, context, 'cluster.yaml')

    def _new_cluster_instance(self, context: dict) -> c.KubernetesCluster:
        return c.KubernetesCluster(self.inventory(), context, self.procedure_inventory(),
                                   self.logger(),
                                   connection_pool=self._connection_pool,
                                   nodes_context=self._nodes_context)

    def _create_logger(self) -> log.EnhancedLogger:
        return log.init_log_from_context_args(
            static.GLOBALS, self.context, str(self.inventory().get('cluster_name', 'cluster.local'))
        ).logger

    def enrichment_functions(self) -> List[c.EnrichmentFunction]:
        # Information about the nodes should be collected within system.detect_nodes_context().
        # All other enrichment procedures should not connect to any node.
        return [
            # JSON validation
            kubemarine.core.schema.verify_connections,
            kubemarine.core.schema.verify_inventory,

            # Early enrichment of procedure inventory for connections
            kubemarine.core.defaults.add_node_enrich_roles,
            kubemarine.core.defaults.enrich_add_nodes,
            kubemarine.core.defaults.calculate_node_names,
            kubemarine.core.defaults.remove_node_enrich_roles,
            kubemarine.core.defaults.enrich_remove_nodes,

            # Merge procedure inventory (not LIGHT)
            kubemarine.admission.manage_enrichment,
            kubemarine.keepalived.enrich_add_node_vrrp_ips,
            kubemarine.keepalived.enrich_remove_node_vrrp_ips,
            kubemarine.plugins.calico.enrich_remove_node_set_previous_typha_enabled,
            kubemarine.kubernetes.enrich_upgrade_inventory,
            kubemarine.kubernetes.enrich_restore_inventory,
            kubemarine.kubernetes.enrich_reconfigure_inventory,
            kubemarine.packages.enrich_procedure_inventory,
            kubemarine.plugins.enrich_upgrade_inventory,
            kubemarine.thirdparties.enrich_procedure_inventory,
            kubemarine.cri.enrich_upgrade_inventory,
            kubemarine.plugins.nginx_ingress.cert_renew_enrichment,
            kubemarine.sysctl.enrich_reconfigure_inventory,
            kubemarine.core.inventory.enrich_reconfigure_inventory,
            # Enrichment of procedure inventory should be finished at this step.

            # Convert formatted inventory to native python objects, and merge defaults.
            kubemarine.core.defaults.restrict_connections,
            kubemarine.core.cluster.KubernetesCluster.convert_formatted_inventory,
            kubemarine.core.defaults.merge_connection_defaults,
            kubemarine.core.defaults.merge_defaults,

            # Pre-compilation
            kubemarine.core.defaults.append_controlplain,

            # Jinja2 compilation
            kubemarine.core.defaults.compile_connections,
            kubemarine.core.defaults.compile_inventory,

            # Early conversion and validation after compilation.
            # Also, complete minimal enrichment of connections.
            kubemarine.core.defaults.calculate_connect_to,
            kubemarine.core.defaults.verify_nodes,
            kubemarine.core.defaults.apply_connection_defaults,
            kubemarine.core.defaults.calculate_nodegroups,
            kubemarine.core.defaults.remove_service_roles,
            kubemarine.kubernetes.verify_roles,
            # Enrichment of inventory for LIGHT stage should be finished at this step.

            # Validation of procedure inventory enrichment after compilation
            kubemarine.kubernetes.verify_version,
            kubemarine.admission.verify_manage_enrichment,
            kubemarine.k8s_certs.renew_verify,
            kubemarine.plugins.nginx_ingress.verify_cert_renew,
            # The functions below depend on kubemarine.kubernetes.verify_version
            kubemarine.kubernetes.verify_upgrade_inventory,
            # Depends on kubemarine.core.defaults.calculate_nodegroups
            kubemarine.packages.verify_procedure_inventory,
            kubemarine.plugins.verify_upgrade_inventory,
            kubemarine.thirdparties.verify_procedure_inventory,
            kubemarine.cri.verify_upgrade_inventory,

            # Remained default enrichment.
            # Many functions depend on kubemarine.core.defaults.calculate_nodegroups
            kubemarine.core.inventory.verify_inventory_patches,
            kubemarine.core.defaults.apply_defaults,
            kubemarine.packages.enrich_inventory,
            kubemarine.core.defaults.apply_registry,
            kubemarine.sysctl.enrich_inventory,
            kubemarine.keepalived.enrich_inventory_apply_defaults,
            kubemarine.keepalived.enrich_inventory_calculate_nodegroup,
            # Depends on kubemarine.keepalived.enrich_inventory_apply_defaults
            kubemarine.haproxy.enrich_inventory,
            # Depends on
            # * kubemarine.core.defaults.apply_registry
            # * kubemarine.sysctl.enrich_inventory
            kubemarine.kubernetes.enrich_inventory,
            kubemarine.admission.enrich_inventory,
            # Depends on kubemarine.core.defaults.apply_defaults
            kubemarine.kubernetes_accounts.enrich_inventory,
            # Depends on kubemarine.kubernetes.enrich_inventory
            kubemarine.cri.enrich_inventory,
            # Depends on kubemarine.core.defaults.apply_registry
            kubemarine.thirdparties.enrich_inventory_apply_defaults,
            # Depends on kubemarine.core.defaults.apply_registry
            kubemarine.plugins.enrich_inventory,
            kubemarine.plugins.verify_inventory,
            kubemarine.plugins.builtin.verify_inventory,
            kubemarine.plugins.calico.enrich_inventory,
            kubemarine.plugins.kubernetes_dashboard.enrich_inventory,
            kubemarine.plugins.local_path_provisioner.enrich_inventory,
            kubemarine.plugins.nginx_ingress.enrich_inventory,
            # Depends on kubemarine.packages.enrich_inventory
            kubemarine.audit.verify_inventory,
            kubemarine.system.verify_inventory,
            kubemarine.system.enrich_etc_hosts,
            kubemarine.modprobe.enrich_kernel_modules,

            # Calculate some differences between previous and new inventory
            # Depends on kubemarine.packages.enrich_inventory
            kubemarine.packages.calculate_upgrade_required,
            # Depends on kubemarine.cri.enrich_inventory
            kubemarine.cri.containerd.calculate_sandbox_image_upgrade_required,

            # Detect and check nodes' context for LIGHT
            kubemarine.core.cluster.KubernetesCluster.init_nodes_context,
            kubemarine.system.detect_nodes_context,
            c.enrichment(c.EnrichmentStage.LIGHT)(kubemarine.core.cluster.KubernetesCluster.check_nodes_accessibility),
        ]

    def finalization_functions(self) -> List[Callable[[c.KubernetesCluster, dict], dict]]:
        return [
            kubemarine.packages.cache_package_versions,
            kubemarine.core.defaults.escape_jinja_characters_for_inventory,
        ]

    def _choose_enrichment_functions(self, stage: c.EnrichmentStage) -> List[c.EnrichmentFunction]:
        procedure = self.context['initial_procedure']
        enrichment_fns = self.enrichment_functions()
        return [fn for fn in enrichment_fns
                if stage in fn.stages
                and (fn.procedures is None or procedure in fn.procedures)]

    def _is_skip_default_enrichment(self) -> bool:
        if self._skip_default_enrichment is None:
            self._skip_default_enrichment = (
                    self._choose_enrichment_functions(c.EnrichmentStage.DEFAULT)
                    == self._choose_enrichment_functions(c.EnrichmentStage.PROCEDURE)
            )

        return self._skip_default_enrichment

    def _get_effective_stage(self, stage: c.EnrichmentStage) -> c.EnrichmentStage:
        if stage == c.EnrichmentStage.DEFAULT and self._is_skip_default_enrichment():
            return c.EnrichmentStage.PROCEDURE

        return stage


RESOURCES_FACTORY = DynamicResources
