from textwrap import dedent

from kubemarine import plugins
from kubemarine.core.action import Action
from kubemarine.core.patch import RegularPatch
from kubemarine.core.resources import DynamicResources


class NginxClusterIPAction(Action):
    def __init__(self) -> None:
        super().__init__("Action to apply ingress nginx patch")

    def run(self, res: DynamicResources) -> None:
        cluster = res.cluster()
        plugins.install(cluster, {'nginx-ingress-controller': cluster.inventory['plugins']['nginx-ingress-controller']})


class NginxClusterIPPatch(RegularPatch):
    def __init__(self) -> None:
        super().__init__("nginx_cluster_ip")

    @property
    def action(self) -> Action:
        return NginxClusterIPAction()

    @property
    def description(self) -> str:
        return dedent(
            f"""\
            This patch changes ingress nginx Service type from LoadBalancer to ClusterIP.
            This is safe change, because we actually do not rely on LoadBalancer type.
            LoadBalancer type actually causes problems if cloud controller manager is installed. 
            """.rstrip()
        )