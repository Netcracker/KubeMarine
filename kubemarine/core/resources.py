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

from typing import Optional

import yaml, os
import ruamel.yaml

from kubemarine.core import utils, cluster as c, log, errors, static


class DynamicResources:
    def __init__(self, context: dict, silent=False):
        self.context = context
        """
        Context holding execution arguments and other auxiliary parameters which manage the execution flow.
        The context can be mutable, but only from action to action,
        and should be copied when passing to the cluster object.
        """

        self._silent = silent
        self._logger = None
        self._raw_inventory = None
        self._formatted_inventory = None
        self._procedure_inventory = None
        self._cluster = None

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
        if not self._silent:
            msg = "Loading inventory file '%s'" % self.inventory_filepath
            if self._logger is None:
                print(msg)
            else:
                self._logger.info(msg)
        try:
            with open(self.inventory_filepath) as f:
                data = yaml.safe_load(f)
            data['node_defaults']['keyfile'] = os.path.expanduser(data['node_defaults']['keyfile'])
            with open(self.inventory_filepath, 'w') as f:
                yaml.safe_dump(data, f, default_flow_style=False)
            with open(self.inventory_filepath, 'r') as stream:
                data = stream.read()
                self._raw_inventory = yaml.safe_load(data)
                # load inventory as ruamel.yaml to save original structure
                self._formatted_inventory = _yaml_structure_preserver().load(data)
        except (yaml.YAMLError, ruamel.yaml.YAMLError) as exc:
            utils.do_fail("Failed to load inventory file", exc, log=self._logger)

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
        with open(self.inventory_filepath, "w+") as stream:
            _yaml_structure_preserver().dump(self.formatted_inventory(), stream)

        self._raw_inventory = None
        self._formatted_inventory = None
        self._cluster = None

    def cluster_if_initialized(self) -> Optional[c.KubernetesCluster]:
        return self._cluster

    def cluster(self) -> c.KubernetesCluster:
        """Returns already initialized cluster object or initializes new cluster object."""
        if self._cluster is None:
            log = self.logger()
            try:
                # temporary cluster instance to detect initial nodes context.
                light_cluster = self._create_cluster()
                light_cluster.enrich(custom_enrichment_fns=light_cluster.get_facts_enrichment_fns())

                # main cluster instance to be used in flow
                cluster = self._create_cluster()
                cluster.enrich(nodes_context=light_cluster.context)

                self._cluster = cluster
            except Exception as exc:
                raise errors.FailException("Failed to proceed inventory file", exc)

            if not self._silent:
                log.debug("Inventory file loaded:")
                for role in self._cluster.roles:
                    log.debug("  %s %i" % (role, len(self._cluster.ips[role])))
                    for ip in self._cluster.ips[role]:
                        log.debug("    %s" % ip)

            args = self.context['execution_arguments']
            if 'ansible_inventory_location' in args:
                utils.make_ansible_inventory(args['ansible_inventory_location'], self._cluster)

        return self._cluster

    def _create_cluster(self):
        return _provide_cluster(self.raw_inventory(), self.context,
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
