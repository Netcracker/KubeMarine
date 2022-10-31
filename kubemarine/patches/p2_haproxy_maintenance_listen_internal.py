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

from kubemarine import haproxy
from kubemarine.core import flow
from kubemarine.core.action import Action
from kubemarine.core.patch import Patch
from kubemarine.core.resources import DynamicResources
from kubemarine.procedures import install


class TheAction(Action):
    def __init__(self):
        super().__init__("Listen internal address in haproxy maintenance mode")

    def run(self, res: DynamicResources):
        cluster = res.cluster()

        if not cluster.nodes.get('balancer') or not haproxy.is_maintenance_mode(cluster):
            cluster.log.info("Skip migration as haproxy is not installed or is not in maintenance mode.")
            return

        not_mixed_balancers = \
            sum(1 for node in cluster.nodes['balancer'].get_ordered_members_list(provide_node_configs=True)
                if len(node['roles']) == 1)

        if not not_mixed_balancers:
            cluster.log.info("All balancers are mixed with some other roles. "
                             "They should not listen internal address. Migration is skipped.")
            return

        flow.run_tasks(res, install.tasks, cumulative_points=install.cumulative_points,
                       tasks_filter=['deploy.loadbalancer.haproxy.configure'])


class HaproxyMaintenanceListenInternal(Patch):
    def __init__(self):
        super().__init__("haproxy_maintenance_listen_internal")

    @property
    def action(self) -> Action:
        return TheAction()

    @property
    def description(self) -> str:
        return """\
Turn on listening of internal address in haproxy maintenance mode for full-HA or non-HA clusters with balancers.
The patch internally runs 'kubemarine install --tasks=deploy.loadbalancer.haproxy.configure'."""
