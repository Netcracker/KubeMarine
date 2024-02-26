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

import unittest
from textwrap import dedent

from kubemarine import demo, kubernetes
from kubemarine.core import summary


class TestInventoryValidation(unittest.TestCase):
    def test_schedule_running_nodes_report(self):
        cluster = demo.new_cluster(demo.generate_inventory(**demo.ALLINONE))
        stdout = dedent(
            """\
            items:
            - metadata:
                labels:
                  node-role.kubernetes.io/control-plane: ""
                  node-role.kubernetes.io/worker: worker
                name: k8s-control-plane-1
              status:
                conditions:
                - status: "False"
                  type: Ready
                - status: "True"
                  type: NetworkUnavailable
            - metadata:
                labels:
                  node-role.kubernetes.io/control-plane: ""
                  node-role.kubernetes.io/worker: worker
                name: k8s-control-plane-2
              status:
                conditions:
                - status: "True"
                  type: Ready
                - status: "False"
                  type: NetworkUnavailable
            - metadata:
                labels:
                  node-role.kubernetes.io/worker: worker
                name: k8s-control-plane-3
              status:
                conditions:
                - status: "True"
                  type: Ready
                - status: "True"
                  type: NetworkUnavailable
            """.rstrip()
        )
        get_nodes = demo.create_nodegroup_result(cluster.nodes['control-plane'], stdout=stdout)
        cluster.fake_shell.add(get_nodes, 'sudo', [kubernetes.get_nodes_description_cmd()])
        kubernetes.exec_running_nodes_report(cluster)
        summary_report = cluster.context.get('summary_report')
        self.assertEqual(
            {
                summary.SummaryItem.CONTROL_PLANES: "1/2",
                summary.SummaryItem.WORKERS: "1/3",
            },
            summary_report
        )


if __name__ == '__main__':
    unittest.main()
