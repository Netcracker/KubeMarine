from textwrap import dedent

from kubemarine.core.action import Action
from kubemarine.core.patch import Patch
from kubemarine.core.resources import DynamicResources
from kubemarine import plugins


class TheAction(Action):
    def __init__(self):
        super().__init__("Correct ingress-nginx on kubernetes v1.25.x")

    def run(self, res: DynamicResources):
        cluster = res.cluster()

        version = cluster.inventory['services']['kubeadm']['kubernetesVersion']
        if '.'.join(version.split('.')[:-1]) != 'v1.25':
            cluster.log.info(f"Patch is not relevant for kubernetes {version}")
            return

        nginx_ingress_plugin = cluster.inventory['plugins']['nginx-ingress-controller']
        if not nginx_ingress_plugin.get('install', False) \
                or nginx_ingress_plugin.get('installation', {}).get('procedures') is None:
            cluster.log.info("nginx-ingress-controller plugin is disabled or its procedures aren't defined")
            return

        cluster.log.info(f"The following plugins will be reinstalled: nginx-ingress-controller")
        plugins.install_plugin(cluster, 'nginx-ingress-controller', nginx_ingress_plugin['installation']['procedures'])



class FixNginxIngress(Patch):
    def __init__(self):
        super().__init__("correct_ingress_nginx")

    @property
    def action(self) -> Action:
        return TheAction()

    @property
    def description(self) -> str:
        return dedent(
            f"""\
            Reinstall nginx-ingress-controller plugin for kubernetes clusters on v1.25.X using corrected template.
            """.rstrip()
        )
