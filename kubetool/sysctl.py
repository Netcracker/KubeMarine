"""
This module works with sysctl on remote systems.
Using this module you can generate new sysctl configs, install and apply them.
"""

import io

from kubetool.core import utils
from kubetool.core.group import NodeGroup, NodeGroupResult


def make_config(cluster):
    """
    Converts parameters from inventory['services']['sysctl'] to a string in the format of systcl.conf.
    """
    config = ""
    if cluster.inventory['services'].get('sysctl') is not None:
        for key, value in cluster.inventory['services']['sysctl'].items():
            if isinstance(value, str):
                value = value.strip()
            if value is not None and value != '':
                if key == "kernel.pid_max":
                    required_pid_max = get_pid_max(cluster.inventory)
                    if value > 2 ** 22:
                        raise Exception(
                            "The 'kernel.pid_max' value = '%s' is greater than the maximum allowable '%s'"
                            % (value, 2 ** 22))
                    if value < required_pid_max:
                        raise Exception(
                            "The 'kernel.pid_max' value = '%s' is lower than "
                            "the minimum required for kubelet configuration = '%s'"
                            % (value, required_pid_max))
                    if value < 32768:
                        cluster.log.warning("The 'kernel.pid_max' value = '%s' is lower than "
                                            "default system value = '32768'" % value)
                config += "%s = %s\n" % (key, value)
        if not cluster.inventory['services']['sysctl'].get("kernel.pid_max"):
            pid_max = get_pid_max(cluster.inventory)
            if pid_max < 32768:
                cluster.log.warning("The 'kernel.pid_max' value = '%s' is lower than "
                                    "default system value = '32768'" % pid_max)
            if pid_max > 2**22:
                raise Exception("Calculated 'pid_max' value = '%s' is greater than the maximum allowable '%s'"
                                % (pid_max, 2**22))
            config += "%s = %s\n" % ("kernel.pid_max", pid_max)
    return config


def configure(group: NodeGroup) -> NodeGroupResult:
    """
    Generates and uploads sysctl configuration to the group.
    The configuration will be placed in sysctl daemon directory.
    """
    config = make_config(group.cluster)
    utils.dump_file(group.cluster, config, '98-kubetools-sysctl.conf')
    group.put(io.StringIO(config), '/etc/sysctl.d/98-kubetools-sysctl.conf', backup=True, sudo=True)
    return group.sudo('ls -la /etc/sysctl.d/98-kubetools-sysctl.conf')


def reload(group: NodeGroup) -> NodeGroupResult:
    """
    Reloads sysctl configuration in the specified group.
    """
    return group.sudo('sysctl -p /etc/sysctl.d/98-kubetools-sysctl.conf')


def get_pid_max(inventory):
    max_pods = inventory["services"]["kubeadm_kubelet"].get("maxPods", 110)
    pod_pids_limit = inventory["services"]["kubeadm_kubelet"].get("podPidsLimit", 4096)
    return max_pods * pod_pids_limit + 2048

