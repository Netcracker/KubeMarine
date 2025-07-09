# Copyright 2021-2023 NetCracker Technology Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from textwrap import dedent

from kubemarine import packages
from kubemarine import kubernetes
from kubemarine.core.action import Action
from kubemarine.core.patch import RegularPatch
from kubemarine.core.resources import DynamicResources
from kubemarine.kubernetes import components


class ContainerdUpgradeAction(Action):
    def __init__(self) -> None:
        super().__init__("Containerd Upgrade")

    def run(self, res: DynamicResources) -> None:
        cluster = res.cluster()

        # this patch is relevant only for ubuntu
        os_family = cluster.get_os_family()
        if os_family != "debian":
            return
        
        # this is a containerd package which we expect to be present on nodes, including version
        containerd_package = packages.get_association_packages(cluster, os_family, "containerd")

        # find hosts where this expected package version is not present
        containerd_hosts = cluster.nodes["control-plane"].include_group(cluster.nodes["worker"]).get_hosts()
        hosts_to_packages = {host: containerd_package for host in containerd_hosts}
        packages_map = packages.detect_installed_packages_version_hosts(cluster, hosts_to_packages)
        bad_hosts = set()
        for package, version_map in packages_map.items():
            package_name = package.replace("*", "")
            for version in version_map.keys():
                if not version.startswith(package_name):
                    for host in version_map[version]:
                        bad_hosts.add(host)
        
        # on these bad hosts, install containerd version as specified in inventory, 
        # but do it carefully with drain, kubelet stop/start, pods sandboxes removal, uncordon, wait for pods
        group = cluster.make_group(bad_hosts)
        log = cluster.log
        first_control_plane = cluster.nodes["control-plane"].get_first_member()
        for node in group.get_ordered_members_list():
            log.debug(f"Containerd will be upgraded on node {node.get_node_name()}")

            # drain the node, but only best-effort
            log.debug(f"Draining node {node.get_node_name()}")
            drain_cmd = kubernetes.prepare_drain_command(cluster, node.get_node_name())
            first_control_plane.sudo(drain_cmd, warn=True, hide=False, pty=True)

            log.debug(f"Stopping kubelet on node: {node.get_node_name()}")
            node.sudo("systemctl stop kubelet")

            log.debug(f"Removing all containers on node: {node.get_node_name()}")
            node.run("for pod in $(sudo crictl pods -q); do " 
                            "sudo crictl inspectp $pod | " 
                            "grep '\"network\": \"NODE\"' > /dev/null || " 
                            "sudo crictl rmp -f $pod; " 
                    "done", warn=True)
            node.sudo("crictl rmp -fa", warn=True)

            cri_packages = cluster.get_package_association_for_node(node.get_host(), 'containerd', 'package_name')
            log.debug(f"Installing {cri_packages} on node: {node.get_node_name()}")
            packages.install(node, include=cri_packages, pty=True)

            log.debug(f"Starting kubelet and uncordon node {node.get_node_name()}")
            node.sudo("systemctl start kubelet")
            # we wait here, because kube-apiserver pod may need to start before uncordon will work
            expect_config = cluster.inventory['globals']['expect']['pods']['kubernetes']
            first_control_plane.wait_command_successful(f"kubectl uncordon {node.get_node_name()}",
                                        timeout=expect_config['timeout'],
                                        retries=expect_config['retries'],
                                        pty=True)

            # we need to make sure that control-plane pods are OK after restart, before moving to next node
            if "control-plane" in node.get_config()["roles"]:
                log.debug(f"Waiting control-plane containers to be ready on node {node.get_node_name()}")
                get_container_from_cri = "sudo crictl ps --name {component} -q"
                get_container_from_pod = (
                    "sudo kubectl get pods -n kube-system {component}-{node} "
                    "-o 'jsonpath={{.status.containerStatuses[0].containerID}}{{\"\\n\"}}' "
                    "| sed 's|.\\+://\\(.\\+\\)|\\1|'")

                test_refreshed_container = (
                    f"("
                    f"CONTAINER=$({get_container_from_cri}); "
                    f"if [ -z \"$CONTAINER\" ]; then "
                    f"  echo \"container '{{component}}' is not created yet\" >&2 ; exit 1; "
                    f"fi "
                    f"&& "
                    f"if [ \"$CONTAINER\" != \"$({get_container_from_pod})\" ]; "
                    f"  then echo \"Pod '{{component}}-{{node}}' is not refreshed yet\" >&2; exit 1; "
                    f"fi "
                    f")")

                commands = []
                for component in components.CONTROL_PLANE_COMPONENTS:
                    commands.append(test_refreshed_container.format(component=component, node=node.get_node_name()))

                node.wait_commands_successful(commands,
                                            timeout=expect_config['timeout'],
                                            retries=expect_config['retries'],
                                            sudo=False, pty=True)
                components.wait_for_pods(node)


class ContainerdUpgrade(RegularPatch):
    def __init__(self) -> None:
        super().__init__("containerd_upgrade")

    @property
    def action(self) -> Action:
        return ContainerdUpgradeAction()

    @property
    def description(self) -> str:
        return dedent(
            f"""\
            This patch upgrades containerd on ubuntu nodes if containerd version is not consistent with cluster.yaml.
            The upgrade is performed per-node: 
            drain, stop kubelet, remove containers, upgrade containerd, start kubelet, uncordon, wait for control plane pods.
            """.rstrip()
        )