from kubemarine import haproxy
from kubemarine.core import flow
from kubemarine.core.action import Action
from kubemarine.core.patch import Patch
from kubemarine.core.resources import DynamicResources
from kubemarine.procedures import install


class TheAction(Action):
    def __init__(self):
        super().__init__("Migrate from not bind VRRP")

    def run(self, res: DynamicResources):
        cluster = res.cluster()
        if not cluster.nodes.get('balancer') or not haproxy.is_maintenance_mode(cluster):
            cluster.log.info("Skip migration as haproxy is not installed or is not in maintenance mode.")
            return

        prev_cluster = res.create_deviated_cluster({
            'p1_migrate_not_bind_vrrp_fix': False
        })
        ctrl_pln = cluster.inventory['control_plain']
        prev_ctrl_pln = prev_cluster.inventory['control_plain']
        if ctrl_pln['internal'] == prev_ctrl_pln['internal'] and ctrl_pln['external'] == prev_ctrl_pln['external']:
            cluster.log.info("Skip migration as control_plain VRRP IP has not changed.")
            return

        group_result = haproxy.get_config_path(cluster.nodes['balancer'])
        for conn, result in group_result.items():
            if result.stdout != haproxy.get_associations_for_node(cluster.get_node(conn))['config_location']:
                raise Exception("Migration is possible only when haproxy is in active mode.")

        flow.run_tasks(res, install.tasks, cumulative_points=install.cumulative_points,
                       tasks_filter=['prepare.dns.etc_hosts', 'deploy.coredns'])


class MigrateNotBindVRRP(Patch):
    def __init__(self):
        super().__init__("migrate_not_bind_vrrp")

    @property
    def action(self) -> Action:
        return TheAction()

    @property
    def description(self) -> str:
        return """\
Migrate from VRRP IP with maintenance-type: not-bind if it was previously chosen as control_plain.
The patch should be run only on cluster with active haproxy mode.
The patch internally runs 'kubemarine install --tasks=prepare.dns.etc_hosts,deploy.coredns'."""
