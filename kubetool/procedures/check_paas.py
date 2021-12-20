#!/usr/bin/env python3
# Copyright 2021 NetCracker Technology Corporation
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


import argparse
import sys
import time
from collections import OrderedDict
import re
from typing import List

import yaml
import ruamel.yaml

from kubetool import packages as pckgs, system, selinux, etcd
from kubetool.core.cluster import KubernetesCluster
from kubetool.procedures import check_iaas
from kubetool.core import flow
from kubetool.testsuite import TestSuite, TestCase, TestFailure, TestWarn


def services_status(cluster, service_type):
    with TestCase(cluster.context['testsuite'], '201', "Services", "%s Status" % service_type.capitalize(),
                  default_results='active (running)'):
        service_name = service_type

        if cluster.inventory['services']['packages']['associations'].get(service_type):
            service_name = cluster.inventory['services']['packages']['associations'][service_type]['service_name']

        group = cluster.nodes['all']
        if service_type == 'haproxy':
            group = cluster.nodes.get('balancer', {})
        elif service_type == 'keepalived':
            group = cluster.nodes.get('keepalived', {})
        elif service_type == 'docker' or service_type == "containerd" or service_type == 'kubelet':
            group = cluster.nodes['master'].include_group(cluster.nodes['worker'])

        if not group or group.is_empty():
            raise TestWarn("No nodes to check service status",
                           hint="The node group to check the service is empty. Check skipped.")

        result = group.sudo('systemctl status %s' % service_name, warn=True)
        cluster.log.verbose(result)

        status_regexp = re.compile("Active:\s([a-z\s()]*)(\ssince|$)", re.M)

        statuses = []
        failed = False
        for connection, node_result in result.items():
            if node_result.return_code == 4:
                statuses.append('service is missing')
                failed = True
                cluster.log.debug('%s is not presented on host %s, skipped'
                                  % (service_type.capitalize(), connection.host))
                continue
            matches = re.findall(status_regexp, node_result.stdout)
            if matches:
                status = matches[0][0].strip()
                cluster.log.debug(
                    '%s status is \"%s\" at host %s' % (service_type.capitalize(), status, connection.host))
                if status != 'active (running)':
                    statuses.append(status)
                    failed = True
            elif node_result.return_code != 0:
                failed = True
                cluster.log.error('%s status has bad exit code \"%s\" at host %s'
                                  % (service_type.capitalize(), node_result.return_code, connection.host))
            else:
                raise Exception('Failed to detect status for \"%s\"' % connection.host)

        statuses = list(set(statuses))

        if failed:
            raise TestFailure("Bad status detected: %s" % ', '.join(statuses),
                              hint="Fix the service to be enabled and has running status.")


def recommended_system_packages_versions(cluster):
    """
    Task which checks if configured "system" packages versions are compatible with configured k8s version and OS.
    Fails if unable to detect OS family.
    Warns if configured not recommended k8s version or if configured not recommended system packages versions.
    """
    with TestCase(cluster.context['testsuite'], '204', "Services", f"Recommended packages version") as tc:
        version_key = system.get_compatibility_version_key(cluster)
        if not version_key:
            raise TestFailure("OS is unknown or multiple OS present")
        k8s_version = cluster.inventory['services']['kubeadm']['kubernetesVersion']
        compatibility = cluster.globals["compatibility_map"]["software"]
        if k8s_version not in compatibility["kubeadm"]:
            raise TestWarn(f"Using not recommended k8s version: {k8s_version}")

        # Mapping "system_package_alias -> expected_packages_names -> expected_versions"
        # We assume that system packages have word "haproxy"/"keepalived"/"docker"/"containerd"/"podman" in their name,
        # if not - then we may miss such package
        expected_system_packages = {
            "haproxy": {"haproxy": compatibility["haproxy"][k8s_version][version_key]},
            "keepalived": {"keepalived": compatibility["keepalived"][k8s_version][version_key]}
        }
        if "docker" in cluster.inventory['services']['cri']['containerRuntime']:
            expected_system_packages["docker"] = {
                "docker": compatibility["docker"][k8s_version][version_key],
                "containerd": compatibility["containerd"][k8s_version][version_key]
            }
        elif "containerd" in cluster.inventory["services"]["cri"]["containerRuntime"]:
            if version_key == "version_rhel":
                expected_system_packages["containerd"] = {
                    "containerd.io": compatibility["containerdio"][k8s_version][version_key],
                    "podman": compatibility["podman"][k8s_version][version_key]
                }
            else:
                expected_system_packages["containerd"] = {
                    "containerd": compatibility["containerd"][k8s_version][version_key],
                    "podman": compatibility["podman"][k8s_version][version_key]
                }

        good_results = set()
        bad_results = []
        for package_alias, expected_packages in expected_system_packages.items():
            actual_packages = cluster.inventory["services"]["packages"]["associations"][package_alias]["package_name"]
            if not isinstance(actual_packages, list):
                actual_packages = [actual_packages]
            for expected_pckg, version in expected_packages.items():
                version = version.replace("*", "")
                is_found = False
                for actual_pckg in actual_packages:
                    if expected_pckg in actual_pckg:
                        is_found = True
                        if f"-{version}" in actual_pckg or f"={version}" in actual_pckg:
                            good_results.add(actual_pckg)
                        else:
                            cluster.log.debug(f"Package {actual_pckg} is not recommended, recommended version is {version}")
                            bad_results.append(actual_pckg)
                if not is_found:
                    cluster.log.debug(f"Package {expected_pckg} is not found in inventory")
                    bad_results.append(expected_pckg)

        if bad_results:
            raise TestWarn("detected not recommended packages versions",
                           hint=f'Check the list of recommended packages and what is listed in the inventory and fix'
                                f'the inconsistencies of the following packages on the system: {bad_results}')
        cluster.log.debug(f"found packages: {good_results}")
        tc.success("all packages have recommended versions")


def system_packages_versions(cluster, pckg_alias):
    """
    Verifies that system packages are installed on required nodes and have equal versions.
    Failure is shown if check is not successful.
    :param cluster: main cluster object.
    :param pckg_alias: system package alias to retrieve "package_name" association.
    """
    with TestCase(cluster.context['testsuite'], '205', "Services", f"{pckg_alias} version") as tc:
        if pckg_alias == "docker" or pckg_alias == "containerd":
            group = cluster.nodes['master'].include_group(cluster.nodes['worker'])
        elif pckg_alias == "keepalived" or pckg_alias == "haproxy":
            if "balancer" in cluster.nodes and not cluster.nodes['balancer'].is_empty():
                group = cluster.nodes['balancer']
            else:
                raise TestWarn("balancer group is not present")
        else:
            raise Exception(f"Unknown system package alias: {pckg_alias}")

        packages = cluster.inventory['services']['packages']['associations'][pckg_alias]['package_name']
        if not isinstance(packages, list):
            packages = [packages]
        return check_packages_versions(cluster, tc, group, packages)


def generic_packages_versions(cluster):
    """
    Verifies that user-provided packages are installed on required nodes and have equal versions.
    Warning is shown if check is not successful.
    """
    with TestCase(cluster.context['testsuite'], '206', "Services", f"Generic packages version") as tc:
        packages = cluster.inventory['services']['packages']['install']['include']
        return check_packages_versions(cluster, tc, cluster.nodes['all'], packages, warn_on_bad_result=True)


def check_packages_versions(cluster, tc, group, packages, warn_on_bad_result=False):
    """
    Verifies that all packages are installed on required nodes and have equal versions
    :param cluster: main cluster object
    :param tc: current test case object
    :param group: nodes where to check packages
    :param packages: list of packages to check
    :param warn_on_bad_result: if true then uses Warning instead of Failure. Default False.
    """
    bad_results = []
    good_results = []

    packages_map = pckgs.detect_installed_packages_version_groups(group, packages)
    for package, version_map in packages_map.items():
        if len(version_map) != 1:
            cluster.log.debug(f"Package {package} has different versions:")
            cluster.log.debug(version_map)
            bad_results.append(package)

        version = list(version_map.keys())[0]
        if "not installed" in version:
            cluster.log.debug(f"Package {package} is not installed on some nodes:")
            cluster.log.debug(version_map[version])
            bad_results.append(package)
        else:
            good_results.append(version)

    if bad_results:
        hint_message = f'Check the presence and correctness of the version of the following packages on the ' \
                       f'system: {bad_results}'
        if warn_on_bad_result:
            raise TestWarn("detected incorrect packages versions", hint=hint_message)
        raise TestFailure("detected incorrect packages versions", hint=hint_message)
    cluster.log.debug(f"installed packages: {good_results}")
    tc.success("all packages have correct versions")


def get_nodes_description(cluster):
    result = cluster.nodes['master'].get_any_member().sudo('kubectl get node -o yaml')
    cluster.log.verbose(result)
    return yaml.safe_load(list(result.values())[0].stdout)


def kubelet_version(cluster):
    with TestCase(cluster.context['testsuite'], '203', "Services", "Kubelet Version",
                  default_results=cluster.inventory['services']['kubeadm']['kubernetesVersion']):
        nodes_description = get_nodes_description(cluster)
        bad_versions = []
        for node_description in nodes_description['items']:
            node_name = node_description['metadata']['name']
            kubelet_version = node_description['status']['nodeInfo']['kubeletVersion']
            cluster.log.debug("Node \"%s\" running kubelet %s" % (node_name, kubelet_version))
            if kubelet_version != cluster.inventory['services']['kubeadm']['kubernetesVersion']:
                bad_versions.append(kubelet_version)
        bad_versions = list(set(bad_versions))
        if bad_versions:
            raise TestFailure("Invalid version detected: %s" % ', '.join(bad_versions),
                              hint="All nodes must have the same correct Kubelet version \"%s\". Remove nodes with the "
                                   "incorrect version from the cluster and reinstall them to the corresponding "
                                   "versions." % cluster.inventory['services']['kubeadm']['kubernetesVersion'])


def thirdparties_hashes(cluster):
    """
    Task which is used to verify configured thirdparties hashes agains actual hashes on nodes.
    If thirdparty is an archive, then archive files hashes are also verified.
    If hash is not specified, then thirdparty is skipped.
    If there is no thirdparties with hashes, then warning is shown.
    """
    with TestCase(cluster.context['testsuite'], '212', "Thirdparties", "Hashes") as tc:
        successful = []
        broken = []

        for path, config in cluster.inventory['services']['thirdparties'].items():
            group = cluster.create_group_from_groups_nodes_names(config.get('groups', []), config.get('nodes', []))
            hosts_missing = find_hosts_missing_thirdparty(group, path)
            if hosts_missing:
                broken.append(f"thirdparty {path} is missing on {hosts_missing}")
                # if thirdparty is missing somewhere, do not check anything further for it
                continue

            if 'sha1' not in config:
                # silently skip if SHA not defined
                continue

            results = group.sudo(f'openssl sha1 {path} | sed "s/^.* //"', warn=True)
            actual_sha = None
            first_host = None
            # Searching actual SHA, if possible
            for host, result in results.items():
                if result.failed:
                    broken.append(f'failed to get {path} sha {host.host}: {result.stderr}')
                    continue

                found_sha = result.stdout.strip()
                if actual_sha is None:
                    actual_sha = found_sha
                    first_host = host.host
                elif actual_sha != found_sha:
                    broken.append(f'got inconsistent sha for {path}: {found_sha} on host {host.host}, '
                                  f'different from first host {first_host} sha {actual_sha}')
                    actual_sha = None
                    break

            expected_sha = config['sha1']  # expected SHA to compare with found actual SHA
            if actual_sha is None:
                # was not able to find single actual SHA, errors already collected, nothing to do
                continue
            if actual_sha != expected_sha:
                broken.append(f'expected sha {expected_sha} is not equal to actual sha {actual_sha} for {path}')
                continue

            successful.append(path)
            # SHA is correct, now check if it is an archive and if it does, then also check SHA for archive content
            if 'unpack' in config:
                unpack_dir = config['unpack']
                res = group.sudo('tar tf %s | grep -vw "./" | while read file_name; do '  # for each file in archive
                                 '  echo ${file_name} '  # print   1) filename
                                 '    $(sudo tar xfO %s ${file_name} | openssl sha1 | cut -d\\  -f2) '  # 2) sha archive
                                 '    $(sudo openssl sha1 %s/${file_name} | cut -d\\  -f2); '  # 3) sha unpacked
                                 'done' % (path, path, unpack_dir))
                # for each file on each host verify that sha in archive is equal to sha for unpacked
                for host, result in res.items():
                    if result.failed:
                        broken.append(f'can not verify files SHA for archive {path} '
                                      f'on host {host.host}, unpacked to {unpack_dir}')
                        continue
                    files_results = result.stdout.strip().split('\n')
                    for file_result in files_results:
                        result_parts = file_result.split()
                        if len(result_parts) != 3:
                            broken.append(f'can not verify files SHA for archive {path} '
                                          f'on host {host.host}, unpacked to {unpack_dir}')
                            continue
                        filename, archive_hash, fs_hash = result_parts[0], result_parts[1], result_parts[2]
                        if archive_hash != fs_hash:
                            broken.append(f'hash for file {filename} from archive {path} '
                                          f'on host {host.host} is not equal to hash for file unpacked to {unpack_dir}')

        if broken:
            raise TestFailure('Found inconsistent hashes', hint=yaml.safe_dump(broken))
        if not successful:
            raise TestWarn('Did not found any hashes')
        tc.success('All found hashes are correct')


def find_hosts_missing_thirdparty(group, path) -> List[str]:
    """
    Search group for a list of hosts where thirdparty is missing
    :param group: group of hosts where to search thirdparty
    :param path: path to thirdparty to search
    :return: list of hosts where thirdparty is missing
    """
    results = group.sudo(f'ls {path}', warn=True)
    missing = []
    for host, result in results.items():
        if result.failed:
            missing.append(host.host)
    return missing


def kubernetes_nodes_existence(cluster):
    with TestCase(cluster.context['testsuite'], '209', "Kubernetes", "Nodes Existence",
                  default_results="All nodes presented"):
        nodes_description = get_nodes_description(cluster)
        not_found = []
        for node in cluster.inventory['nodes']:
            if 'master' in node['roles'] or 'worker' in node['roles']:
                found = False
                for node_description in nodes_description['items']:
                    node_name = node_description['metadata']['name']
                    if node_name == node['name']:
                        found = True
                        break
                if found:
                    cluster.log.debug("Node \"%s\" is found in cluster" % node['name'])
                else:
                    not_found.append(node['name'])
                    cluster.log.error("Node \"%s\" is not found in cluster" % node['name'])
        not_found = list(set(not_found))
        if not_found:
            raise TestFailure("Nodes not found: %s" % ', '.join(not_found),
                              hint="The cluster must contain all the nodes that are described in the inventory. Add "
                                   "the missing nodes to cluster.")


def kubernetes_nodes_roles(cluster):
    with TestCase(cluster.context['testsuite'], '210', "Kubernetes", "Nodes Roles",
                  default_results="All nodes have the correct roles"):
        nodes_description = get_nodes_description(cluster)
        nodes_with_bad_roles = []
        for node in cluster.inventory['nodes']:
            for node_description in nodes_description['items']:
                node_name = node_description['metadata']['name']
                if node['name'] == node_name:
                    if 'master' in node['roles']:
                        if 'node-role.kubernetes.io/master' not in node_description['metadata']['labels']:
                            nodes_with_bad_roles.append(node['name'])
                            cluster.log.error("Node \"%s\" has to be master, but has invalid role" % node['name'])
                        else:
                            cluster.log.debug("Node \"%s\" has correct master role" % node['name'])
                    elif 'worker' in node['roles']:
                        if 'node-role.kubernetes.io/worker' not in node_description['metadata']['labels']:
                            nodes_with_bad_roles.append(node['name'])
                            cluster.log.error("Node \"%s\" has to be worker, but has invalid role" % node['name'])
                        else:
                            cluster.log.debug("Node \"%s\" has correct worker role" % node['name'])
                    break
        nodes_with_bad_roles = list(set(nodes_with_bad_roles))
        if nodes_with_bad_roles:
            raise TestFailure("Incorrect role detected at: %s" % ', '.join(nodes_with_bad_roles),
                              hint="There were detected some nodes, whose role differs from that specified in the "
                                   "inventory. The configuration of these nodes should be fixed.")


def kubernetes_nodes_condition(cluster, condition_type):
    with TestCase(cluster.context['testsuite'], '211', "Kubernetes", "Nodes Condition - %s" % condition_type) as tc:
        nodes_description = get_nodes_description(cluster)
        expected_status = 'False'
        if condition_type == 'Ready':
            expected_status = 'True'
        positive_conditions = []
        negative_conditions = []
        for node_description in nodes_description['items']:
            node_name = node_description['metadata']['name']
            condition_found = False
            for condition in node_description['status']['conditions']:
                if condition['type'] == condition_type:
                    condition_found = True
                    cluster.log.debug("Node \"%s\" condition \"%s\" is \"%s\""
                                      % (node_name, condition['type'], condition['reason']))
                    if condition['status'] != expected_status:
                        negative_conditions.append(condition['reason'])
                    else:
                        positive_conditions.append(condition['reason'])
                    break
            if not condition_found:
                raise TestFailure("Failed to detect at %s" % node_name)

        negative_conditions = list(set(negative_conditions))
        positive_conditions = list(set(positive_conditions))

        if negative_conditions:
            raise TestFailure("%s" % ', '.join(negative_conditions),
                              hint="A condition in negative status means that there are problems with the health of "
                                   "the node.")

        tc.success(results="%s" % ', '.join(positive_conditions))


def get_not_running_pods(cluster):
    get_pods_cmd = 'kubectl get pods -A --field-selector status.phase!=Running | awk \'{ print $1" "$2" "$4 }\''
    result = cluster.nodes['master'].get_any_member().sudo(get_pods_cmd)
    cluster.log.verbose(result)
    return list(result.values())[0].stdout.strip()


def kubernetes_pods_condition(cluster):
    system_namespaces = ["kube-system", "ingress-nginx", "kube-public", "kubernetes-dashboard", "default"]
    critical_states = cluster.globals['pods']['critical_states']
    with TestCase(cluster.context['testsuite'], '207', "Kubernetes", "Pods Condition") as tc:
        pods_description = get_not_running_pods(cluster)
        total_failed_amount = len(pods_description.split('\n')[1:])
        critical_system_failed_amount = 0

        for pod_description in pods_description.split('\n')[1:]:
            split_description = pod_description.split(' ')
            if split_description[0] in system_namespaces and split_description[2] in critical_states:
                critical_system_failed_amount += 1

        if critical_system_failed_amount > 0:
            s = ''
            if critical_system_failed_amount != 1:
                s = 's'
            raise TestFailure("%s failed system pod%s" % (critical_system_failed_amount, s),
                              hint="Try to determine the cause of pods failure, redeploy, reapply or restart them. If "
                                   "this is not fixed, the cluster may not work or do it incorrectly.")
        elif total_failed_amount > 0:
            s = ''
            if total_failed_amount != 1:
                s = 's'
            raise TestWarn("%s pod%s are failed/not running" % (total_failed_amount, s),
                           hint="Try to determine the reason the pods are not operational, "
                                "try to wait, redeploy, reapply or restart them. "
                                "If this is not fixed, some deployed applications may not work or do it incorrectly.")
        else:
            tc.success(results="All pods are running")


def kubernetes_dashboard_status(cluster):
    with TestCase(cluster.context['testsuite'], '208', "Plugins", "Dashboard Availability") as tc:
        retries = 10
        test_succeeded = False
        i = 0
        while not test_succeeded and i < retries:
            i += 1
            if cluster.inventory['plugins']['kubernetes-dashboard']['install']:
                results = cluster.nodes['master'].get_first_member().sudo("kubectl get svc -n kubernetes-dashboard kubernetes-dashboard -o=jsonpath=\"{['spec.clusterIP']}\"", warn=True)
                for master, result in results.items():
                    if result.failed:
                       cluster.log.debug(f'Can not resolve dashboard IP: {result.stderr} ')
                       raise TestFailure("not available",hint=f"Please verify the following Kubernetes Dashboard status and fix this issue")
                found_url = result.stdout
                check_url = cluster.nodes['master'].get_first_member().sudo(f'curl -k -I https://{found_url}:443', warn=True)
                status = list(check_url.values())[0].stdout
                if '200' in status:
                    cluster.log.debug(status)
                    test_succeeded = True
                    tc.success(results="available")
                else:
                    cluster.log.debug(f'Dashboard is not running yet... Retries left: {retries - i}')
                    time.sleep(60)
            else:
                test_succeeded = True
                tc.success(results="skipped")
        if not test_succeeded:
            raise TestFailure("not available",
                              hint=f"Please verify the following Kubernetes Dashboard status and fix this issue:\n{status}")


def nodes_pid_max(cluster):
    with TestCase(cluster.context['testsuite'], '202', "Nodes", "Nodes pid_max correctly installed") as tc:
        master = cluster.nodes['master'].get_any_member()
        yaml = ruamel.yaml.YAML()
        nodes_failed_pid_max_check = {}
        for node in cluster.nodes['master'].include_group(cluster.nodes['worker']).get_ordered_members_list(provide_node_configs=True):

            node_info = master.sudo("kubectl get node %s -o yaml" % node["name"]).get_simple_out()
            config = yaml.load(node_info)
            max_pods = int(config['status']['capacity']['pods'])

            kubelet_config = node["connection"].sudo("cat /var/lib/kubelet/config.yaml").get_simple_out()
            config = yaml.load(kubelet_config)
            pod_pids_limit = int(config['podPidsLimit'])

            pid_max = int(node["connection"].sudo("cat /proc/sys/kernel/pid_max").get_simple_out())
            required_pid_max = max_pods * pod_pids_limit + 2048
            cluster.log.debug("Current values:\n maxPods = %s \n podPidsLimit = %s \n pid_max = %s"
                              % (max_pods, pod_pids_limit, pid_max))
            cluster.log.debug("Required pid_max for current kubelet configuration is %s for node '%s'"
                              % (required_pid_max, node["name"]))
            if cluster.inventory['services']['sysctl'].get("kernel.pid_max"):
                inventory_pid_max = cluster.inventory['services']['sysctl'].get("kernel.pid_max")
                if pid_max != inventory_pid_max:
                    raise TestWarn("The 'kernel.pid_max' value defined in system = %s, "
                                   "but 'kernel.pid_max', which defined in cluster.yaml = %s"
                                   % (pid_max, inventory_pid_max))
            if pid_max < required_pid_max:
                nodes_failed_pid_max_check[node["name"]] = [pid_max, required_pid_max]

        if nodes_failed_pid_max_check:
            output = "The requirement for the 'pid_max' value is not met for nodes:\n"
            for node in nodes_failed_pid_max_check:
                output += ("For node %s pid_max value = '%s', but it should be >= then '%s'\n"
                           % (node, nodes_failed_pid_max_check[node][0], nodes_failed_pid_max_check[node][1]))
            raise TestFailure(output)
        tc.success(results="pid_max correctly installed on all nodes")


def verify_selinux_status(cluster: KubernetesCluster) -> None:
    """
    This method is a test, which checks the status of Selinux. It must be `enforcing`. It may be `permissive`, but must
    be explicitly specified in the inventory. Otherwise, the test will fail. This test is applicable only for systems of
    the RHEL family.
    :param cluster: KubernetesCluster object
    :return: None
    """
    if system.get_os_family(cluster) == 'debian':
        return

    with TestCase(cluster.context['testsuite'], '213', "Security", "Selinux security policy") as tc:
        group = cluster.nodes['all']
        selinux_configured, selinux_result, selinux_parsed_result = \
            selinux.is_config_valid(group,
                                    state=selinux.get_expected_state(cluster.inventory),
                                    policy=selinux.get_expected_policy(cluster.inventory),
                                    permissive=selinux.get_expected_permissive(cluster.inventory))
        cluster.log.debug(selinux_result)
        enforcing_ips = []
        permissive_ips = []
        bad_ips = []
        for conn, results in selinux_parsed_result.items():
            if results['mode'] == 'enforcing':
                enforcing_ips.append(conn.host)
            elif results['mode'] == 'permissive' and cluster.inventory.get('services', {})\
                    .get('kernel_security', {}).get('selinux', {}).get('state') == 'permissive':
                permissive_ips.append(conn.host)
            else:
                bad_ips.append([conn.host, results['mode']])

        if group.nodes_amount() == len(enforcing_ips):
            tc.success(results='enforcing')
        elif len(bad_ips) == 0:
            pretty_list = '\n - ' + ('\n - '.join(permissive_ips))
            raise TestWarn('permissive',
                           hint=f"It is not recommended to use permissive state, but this is possible if you "
                                f"explicitly specify this in your inventory, thereby assuming all risks. Only "
                                f"\"enforcing\" policy is recommended. Please use it on the following "
                                f"nodes:{pretty_list}")
        else:
            bad_states = []
            pretty_list_ips = []
            for ip_state in bad_ips:
                ip = ip_state[0]
                state = ip_state[1]
                if state not in bad_states:
                    bad_states.append(state)
                if ip not in pretty_list_ips:
                    pretty_list_ips.append(ip)
            pretty_list = '\n - ' + ('\n - '.join(pretty_list_ips))
            raise TestFailure(', '.join(bad_states),
                              hint=f"Selinux is configured with wrong state, which is not recommended. Only "
                                   f"\"enforcing\" policy is recommended. Please use it on the following "
                                   f"nodes:{pretty_list}")


def verify_selinux_config(cluster: KubernetesCluster) -> None:
    """
    This method is a test, which compares the configuration of Selinux on the nodes with the configuration specified in
    the inventory or with the one by default. If the configuration does not match, the test will fail.
    :param cluster: KubernetesCluster object
    :return: None
    """
    if system.get_os_family(cluster) == 'debian':
        return

    with TestCase(cluster.context['testsuite'], '214', "Security", "Selinux configuration") as tc:
        group = cluster.nodes['all']
        selinux_configured, selinux_result, selinux_parsed_result = \
            selinux.is_config_valid(group,
                                    state=selinux.get_expected_state(cluster.inventory),
                                    policy=selinux.get_expected_policy(cluster.inventory),
                                    permissive=selinux.get_expected_permissive(cluster.inventory))
        cluster.log.debug(selinux_result)
        if selinux_configured:
            tc.success(results='valid')
        else:
            raise TestFailure('invalid',
                              hint=f"Selinux is incorrectly configured - its configuration is different from the one "
                                   f"specified in the inventory. Check the configuration and run the selinux setup task"
                                   f" via installation procedure.")


def verify_firewalld_status(cluster: KubernetesCluster) -> None:
    """
    This method is a test, which verifies that the FirewallD is disabled on cluster nodes, otherwise the test will fail.
    :param cluster: KubernetesCluster object
    :return: None
    """
    with TestCase(cluster.context['testsuite'], '215', "Security", "Firewalld status") as tc:
        group = cluster.nodes['all']
        firewalld_disabled, firewalld_result = system.is_firewalld_disabled(group)
        cluster.log.debug(firewalld_result)
        if firewalld_disabled:
            tc.success(results='disabled')
        else:
            raise TestFailure('enabled',
                              hint=f"FirewallD must be disabled as it is not supported and can create compatibility "
                                   f"issues. To solve this problem, execute firewalld disable task in the installation "
                                   f"procedure.")


def verify_swap_state(cluster: KubernetesCluster) -> None:
    """
    This method is a test, which verifies that swap is disabled on all nodes in the cluster, otherwise the test will
    fail.
    :param cluster: KubernetesCluster object
    :return: None
    """
    with TestCase(cluster.context['testsuite'], '216', "System", "Swap state") as tc:
        group = cluster.nodes['all']
        swap_disabled, swap_result = system.is_swap_disabled(group)
        cluster.log.debug(swap_result)
        if swap_disabled:
            tc.success(results='disabled')
        else:
            raise TestFailure('enabled',
                              hint=f"Swap must be disabled as it is not supported and can create performance "
                                   f"issues. To solve this problem, execute swap disable task in the installation "
                                   f"procedure.")


def verify_modprobe_rules(cluster: KubernetesCluster) -> None:
    """
    This method is a test, which compares the modprobe rules on the nodes with the rules specified in the inventory or
    with default rules. If rules does not match, the test will fail.
    :param cluster: KubernetesCluster object
    :return: None
    """
    with TestCase(cluster.context['testsuite'], '217', "System", "Modprobe rules") as tc:
        group = cluster.nodes['all']
        modprobe_valid, modprobe_result = system.is_modprobe_valid(group)
        cluster.log.debug(modprobe_result)
        if modprobe_valid:
            tc.success(results='valid')
        else:
            raise TestFailure('invalid',
                              hint=f"Modprobe rules do not match those loaded in modprobe on cluster nodes. Check "
                                   f"manually what the differences are and make changes on the appropriate nodes.")


def etcd_health_status(cluster):
    """
    This method is a test, check ETCD health
    """
    with TestCase(cluster.context['testsuite'], '218', "etcd", "health_status") as tc:
        try:
            etcd_health_status = etcd.wait_for_health(cluster, cluster.nodes['master'].get_any_member())
        except Exception as e:
            cluster.log.verbose('Failed to load and parse ETCD status')
            raise TestFailure('invalid',
                              hint=f"ETCD not ready, please check"
                                   f"because of {e}")
        cluster.log.debug(etcd_health_status)
        tc.success(results='valid')


tasks = OrderedDict({
    'services': {
        'security': {
            'selinux': {
                'status': verify_selinux_status,
                'config': verify_selinux_config
            },
            # TODO: support apparmor validation
            # 'apparmor': {
            #     'status': None,
            #     'config': None
            # },
            'firewalld': {
                'status': verify_firewalld_status
            }
        },
        'system': {
            'swap': {
                'status': verify_swap_state
            },
            'modprobe': {
                'rules': verify_modprobe_rules
            }
        },
        'haproxy': {
            'status': lambda cluster: services_status(cluster, 'haproxy'),
        },
        'keepalived': {
            'status': lambda cluster: services_status(cluster, 'keepalived'),
        },
        'container_runtime': {
            'status': lambda cluster:
                services_status(cluster, cluster.inventory['services']['cri']['containerRuntime']),
        },
        'kubelet': {
            'status': lambda cluster: services_status(cluster, 'kubelet'),
            'configuration': lambda cluster: nodes_pid_max(cluster),
            'version': kubelet_version,
        },
        'packages': {
            'system': {
                'recommended_versions': recommended_system_packages_versions,
                'cri_version': lambda cluster:
                    system_packages_versions(cluster, cluster.inventory['services']['cri'][ 'containerRuntime']),
                'haproxy_version': lambda cluster: system_packages_versions(cluster, 'haproxy'),
                'keepalived_version': lambda cluster: system_packages_versions(cluster, 'keepalived')
            },
            'generic': {
                'version': generic_packages_versions
            }
        },
    },
    'thirdparties': {
        'hashes': thirdparties_hashes,
    },
    'kubernetes': {
        'pods': kubernetes_pods_condition,
        'plugins': {
            'dashboard': kubernetes_dashboard_status
        },
        'nodes': {
            'existence': kubernetes_nodes_existence,
            'roles': kubernetes_nodes_roles,
            'condition': {
                "network": lambda cluster: kubernetes_nodes_condition(cluster, 'NetworkUnavailable'),
                "memory": lambda cluster: kubernetes_nodes_condition(cluster, 'MemoryPressure'),
                "disk": lambda cluster: kubernetes_nodes_condition(cluster, 'DiskPressure'),
                "pid": lambda cluster: kubernetes_nodes_condition(cluster, 'PIDPressure'),
                "ready": lambda cluster: kubernetes_nodes_condition(cluster, 'Ready')
            },
        },
    },
    'etcd': {
        "health_status": etcd_health_status
    },
})


def main(cli_arguments=None):
    parser = argparse.ArgumentParser(description='''
Script for checking Kubernetes cluster PAAS layer.

Hot to use:

''', formatter_class=argparse.RawTextHelpFormatter)

    parser.add_argument('-v', '--verbose',
                        action='store_true',
                        help='enable the verbosity mode')

    parser.add_argument('-c', '--config',
                        default='cluster.yaml',
                        help='define main cluster configuration file')

    parser.add_argument('--tasks',
                        default='',
                        help='define comma-separated tasks to be executed')

    parser.add_argument('--exclude',
                        default='',
                        help='exclude comma-separated tasks from execution')

    parser.add_argument('--csv-report',
                        default='report.csv',
                        help='define CSV report file location')

    parser.add_argument('--csv-report-delimiter',
                        default=';',
                        help='define delimiter type for CSV report')

    parser.add_argument('--html-report',
                        default='report.html',
                        help='define HTML report file location')

    parser.add_argument('--disable-csv-report',
                        action='store_true',
                        help='forcibly disable CSV report file creation')

    parser.add_argument('--disable-html-report',
                        action='store_true',
                        help='forcibly disable HTML report file creation')

    if cli_arguments is None:
        args = parser.parse_args()
    else:
        args = parser.parse_args(cli_arguments)

    defined_tasks = []
    defined_excludes = []

    if args.tasks != '':
        defined_tasks = args.tasks.split(",")

    if args.exclude != '':
        defined_excludes = args.exclude.split(",")

    context = flow.create_context(args, procedure='paas',
                                  included_tasks=defined_tasks, excluded_tasks=defined_excludes)
    context['testsuite'] = TestSuite()

    cluster = flow.run(
        tasks,
        defined_tasks,
        defined_excludes,
        args.config,
        context,
        print_final_message=False
    )

    # Final summary should be printed only to stdout with custom formatting
    # If tests results required for parsing, they can be found in test results files
    print(cluster.context['testsuite'].get_final_summary(show_minimal=False, show_recommended=False))
    cluster.context['testsuite'].print_final_status(cluster.log)
    check_iaas.make_reports(cluster)
    return cluster.context['testsuite']


if __name__ == '__main__':
    testsuite = main()
    if testsuite.is_any_test_failed():
        sys.exit(1)
