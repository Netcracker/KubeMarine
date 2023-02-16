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
from contextlib import contextmanager
from copy import deepcopy
from typing import Optional

import yaml
import ruamel.yaml

from kubemarine.core import utils, cluster as c, log, errors, static
from kubemarine.core.yaml_merger import default_merger


class DynamicResources:
    def __init__(self, context: dict, silent=False):
        self.context = context
        """
        Context holding execution arguments and other auxiliary parameters which manage the execution flow.
        The context can be mutable, but only from action to action,
        and should be copied when passing to the cluster object.
        """
        self.working_context = context
        """
        Context that is directly passed to the cluster object and that holds its intermediate result.
        """

        self._silent = silent
        self._logger: Optional[log.EnhancedLogger] = None
        self._raw_inventory = None
        self._formatted_inventory = None
        self._procedure_inventory = None

        self._nodes_context = None
        """
        The nodes_context variable should hold node specific information that is not changed during Kubemarine run.
        The variable should be initialized on demand and only once.
        """

        self._cluster: Optional[c.KubernetesCluster] = None

        args: dict = context['execution_arguments']
        self.inventory_filepath = args['config']
        self.procedure_inventory_filepath = args.get('procedure_config')

    def logger(self):
        if self._logger is None:
            self._logger = self._create_logger()

        return self._logger

    def raw_inventory(self) -> dict:
        """Returns raw inventory, which does not preserve formatting and which should be read only."""
        if self._raw_inventory is None:
            self._load_inventory()

        return self._raw_inventory

    def formatted_inventory(self) -> dict:
        """Returns raw inventory with preserved comments/quotes, to be modified and later recreated."""
        if self._formatted_inventory is None:
            self._load_inventory()

        return self._formatted_inventory

    def procedure_inventory(self):
        if self._procedure_inventory is None and self.procedure_inventory_filepath:
            self._procedure_inventory = utils.load_yaml(self.procedure_inventory_filepath)

        return self._procedure_inventory

    def _load_inventory(self):
        logger = self._logger
        if not self._silent:
            msg = "Loading inventory file '%s'" % self.inventory_filepath
            if logger is None:
                print(msg)
            else:
                logger.info(msg)
        try:
            data = utils.read_external(self.inventory_filepath)
            self._raw_inventory = yaml.safe_load(data)
            # load inventory as ruamel.yaml to save original structure
            self._formatted_inventory = _yaml_structure_preserver().load(data)
        except (yaml.YAMLError, ruamel.yaml.YAMLError) as exc:
            utils.do_fail("Failed to load inventory file", exc, log=logger)

    def make_final_inventory(self):
        self._formatted_inventory = utils.get_final_inventory(self.cluster(), initial_inventory=self.formatted_inventory())

    def recreate_inventory(self):
        """
        Recreates initial inventory file using DynamicResources.formatted_inventory and resets all dynamic resources.

        Avoid using it directly, because cluster object and previous inventory will be lost,
        and post processing of actions may work incorrectly.
        """
        if self._formatted_inventory is None:
            return

        # replace initial inventory file with changed inventory
        with utils.open_external(self.inventory_filepath, "w+") as stream:
            _yaml_structure_preserver().dump(self.formatted_inventory(), stream)

        self._raw_inventory = None
        self._formatted_inventory = None
        # no need to clear _nodes_context as it should not change after cluster is reinitialized.
        # should not clear working_context as it can be inspected after execution.
        self._cluster = None

    def cluster_if_initialized(self) -> Optional[c.KubernetesCluster]:
        return self._cluster

    def cluster(self) -> c.KubernetesCluster:
        """Returns already initialized cluster object or initializes new real cluster object."""
        if self._cluster is None:
            self.working_context = deepcopy(self.context)
            self._cluster = self._create_cluster(self.working_context)

        return self._cluster

    def create_deviated_cluster(self, deviated_context: dict):
        """
        Create new cluster instance with specified deviation of context params.
        The method work should minimize work with network and avoid RW work with filesystem.
        The cluster instance should be useful to develop a patch in case enrichment procedure is changed
        and it is necessary to compare the result of old and new algorithm of enrichment.
        It should not be used in tasks.

        :param deviated_context dictionary to override context params.
        """
        sample_context = deepcopy(self.context)
        default_merger.merge(sample_context, deviated_context)
        sample_context['preserve_inventory'] = False
        args = sample_context['execution_arguments']
        args['disable_dump'] = True
        del args['ansible_inventory_location']
        return self._create_cluster(sample_context)

    @contextmanager
    def _handle_enrichment_error(self):
        try:
            yield
        except errors.FailException:
            raise
        except Exception as exc:
            raise errors.FailException("Failed to proceed inventory file", exc)

    def _create_cluster(self, context):
        log = self.logger()
        context['nodes'] = deepcopy(self._get_nodes_context())
        with self._handle_enrichment_error():
            cluster = self._new_cluster_instance(context)
            cluster.enrich()

        if not self._silent:
            log.debug("Inventory file loaded:")
            for role in cluster.roles:
                log.debug("  %s %i" % (role, len(cluster.ips[role])))
                for ip in cluster.ips[role]:
                    log.debug("    %s" % ip)

        args = context['execution_arguments']
        if 'ansible_inventory_location' in args:
            utils.make_ansible_inventory(args['ansible_inventory_location'], cluster)

        return cluster

    def _get_nodes_context(self):
        if self._nodes_context is None:
            with self._handle_enrichment_error():
                # temporary cluster instance to detect initial nodes context.
                light_cluster = self._new_cluster_instance(deepcopy(self.context))
                light_cluster.enrich(custom_enrichment_fns=light_cluster.get_facts_enrichment_fns())
                self._nodes_context = light_cluster.detect_nodes_context()

        return self._nodes_context

    def _new_cluster_instance(self, context: dict):
        return _provide_cluster(self.raw_inventory(), context,
                                procedure_inventory=self.procedure_inventory(),
                                logger=self.logger())

    def _create_logger(self):
        return log.init_log_from_context_args(static.GLOBALS, self.context, self.raw_inventory()).logger


def _yaml_structure_preserver():
    """YAML loader and dumper which saves original structure"""
    ruamel_yaml = ruamel.yaml.YAML()
    ruamel_yaml.preserve_quotes = True
    return ruamel_yaml


def _provide_cluster(*args, **kw):
    from kubemarine.core import flow
    return flow.DEFAULT_CLUSTER_OBJ(*args, **kw) if flow.DEFAULT_CLUSTER_OBJ is not None \
        else c.KubernetesCluster(*args, **kw)
