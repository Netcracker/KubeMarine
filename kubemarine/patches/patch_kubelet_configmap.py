from textwrap import dedent

from kubemarine.core.action import Action
from kubemarine.core.patch import RegularPatch
from kubemarine.core.resources import DynamicResources
from kubemarine.kubernetes import components


class TheAction(Action):
    def __init__(self) -> None:
        super().__init__("Remove default resolvConf from kubelet-config ConfigMap")

    def run(self, res: DynamicResources) -> None:
        cluster = res.cluster()
        control_plane = cluster.nodes['control-plane'].get_first_member()

        kubeadm_config = components.KubeadmConfig(cluster)
        if 'resolvConf' in kubeadm_config.maps['kubelet-config']:
            return cluster.log.info("KubeletConfiguration.resolvConf is redefined in the inventory. "
                                    "Patch is not applicable.")

        if 'resolvConf' not in kubeadm_config.load('kubelet-config', control_plane):
            return cluster.log.info("KubeletConfiguration.resolvConf is already absent in the kubelet-config ConfigMap.")

        control_plane.call(components.patch_kubelet_configmap)


class KubeletResolvConf(RegularPatch):
    def __init__(self) -> None:
        super().__init__("kubelet_resolvConf")

    @property
    def action(self) -> Action:
        return TheAction()

    @property
    def description(self) -> str:
        return dedent(
            f"""\
            If KubeletConfiguration.resolvConf is not redefined in the inventory,
            remove it from the kubelet-config ConfigMap if present.
            
            This is necessary for smoother migration of the operating systems.
            """.rstrip()
        )
