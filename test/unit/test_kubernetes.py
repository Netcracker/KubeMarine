import unittest
from textwrap import dedent

from kubemarine import demo, kubernetes
from kubemarine.core import utils


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
            - metadata:
                labels:
                  node-role.kubernetes.io/control-plane: ""
                  node-role.kubernetes.io/worker: worker
                name: k8s-control-plane-2
              status:
                conditions:
                - status: "True"
                  type: Ready
            - metadata:
                labels:
                  node-role.kubernetes.io/worker: worker
                name: k8s-control-plane-3
              status:
                conditions:
                - status: "True"
                  type: Ready
            """.rstrip()
        )
        get_nodes = demo.create_nodegroup_result(cluster.nodes['control-plane'], stdout=stdout)
        cluster.fake_shell.add(get_nodes, 'sudo', [kubernetes.get_nodes_description_cmd()])
        kubernetes.schedule_running_nodes_report(cluster)
        summary_report = cluster.context.get('summary_report')
        self.assertEquals(
            {
                utils.SummaryItem.CONTROL_PLANES: "1/2",
                utils.SummaryItem.WORKERS: "2/3",
            },
            summary_report
        )


if __name__ == '__main__':
    unittest.main()
