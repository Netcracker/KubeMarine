#!/usr/bin/env python3
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
import io
import sys
import time
from collections import OrderedDict
import re
from textwrap import dedent
from typing import List, Dict, Optional

import yaml
import ruamel.yaml
import ipaddress
import uuid

from kubemarine import packages as pckgs, system, selinux, etcd, thirdparties, apparmor, kubernetes
from kubemarine.core.action import Action
from kubemarine.core.cluster import KubernetesCluster
from kubemarine.core.group import NodeConfig, NodeGroup
from kubemarine.core.resources import DynamicResources
from kubemarine.cri import containerd
from kubemarine.plugins import calico
from kubemarine.procedures import check_iaas
from kubemarine.core import flow, static
from kubemarine.testsuite import TestSuite, TestCase, TestFailure, TestWarn
from kubemarine.kubernetes.daemonset import DaemonSet
from kubemarine.kubernetes.deployment import Deployment
from kubemarine.kubernetes.object import KubernetesObject
from kubemarine.coredns import generate_configmap
from deepdiff import DeepDiff  # type: ignore[import]


def services_status(cluster: KubernetesCluster, service_type: str) -> None:
    with TestCase(cluster, '201', "Services", "%s Status" % service_type.capitalize(),
                  default_results='active (running)'):
        service_name = service_type

        if cluster.get_os_family() != 'multiple' and service_type != 'kubelet':
            service_name = cluster.get_package_association(service_type, 'service_name')

        group = cluster.nodes['all']
        if service_type == 'haproxy':
            group = cluster.make_group_from_roles(['balancer'])
        elif service_type == 'keepalived':
            group = cluster.make_group_from_roles(['keepalived'])
        elif service_type == 'docker' or service_type == "containerd" or service_type == 'kubelet':
            group = cluster.make_group_from_roles(['control-plane', 'worker'])

        if group.is_empty():
            raise TestWarn("No nodes to check service status",
                           hint="The node group to check the service is empty. Check skipped.")

        result = group.sudo('systemctl status %s' % service_name, warn=True)
        cluster.log.verbose(result)

        status_regexp = re.compile("Active:\s([a-z\s()]*)(\ssince|$)", re.M)

        statuses = []
        failed = False
        for host, node_result in result.items():
            if node_result.return_code == 4:
                statuses.append('service is missing')
                failed = True
                cluster.log.debug('%s is not presented on host %s, skipped'
                                  % (service_type.capitalize(), host))
                continue
            matches = re.findall(status_regexp, node_result.stdout)
            if matches:
                status = matches[0][0].strip()
                cluster.log.debug(
                    '%s status is \"%s\" at host %s' % (service_type.capitalize(), status, host))
                if status != 'active (running)':
                    statuses.append(status)
                    failed = True
            elif node_result.return_code != 0:
                failed = True
                cluster.log.error('%s status has bad exit code \"%s\" at host %s'
                                  % (service_type.capitalize(), node_result.return_code, host))
            else:
                raise Exception('Failed to detect status for \"%s\"' % host)

        statuses = list(set(statuses))

        if failed:
            raise TestFailure("Bad status detected: %s" % ', '.join(statuses),
                              hint="Fix the service to be enabled and has running status.")


def _check_same_os(cluster: KubernetesCluster) -> None:
    os_ids = cluster.get_os_identifiers()
    different_os = set(os_ids.values())
    if len(different_os) > 1:
        cluster.log.warning(
            f"Nodes have different OS families or versions, packages versions cannot be checked. "
            f"List of (OS family, version): {list(different_os)}")
        raise TestFailure(f"Nodes have different OS families or versions")


def recommended_system_package_versions(cluster: KubernetesCluster, pckg_alias: str) -> None:
    """
    Function that checks if defined package are compatible with the configured k8s version and OS.
    Raise Warn if unable to detect the OS family, configured not recommended k8s version or
    if configured not recommended system packages versions.
    """
    os_family = cluster.get_os_family()
    if os_family not in pckgs.get_associations_os_family_keys():
        raise TestFailure("OS is unknown or multiple OS present")

    recommended_packages = list(static.GLOBALS['packages'][os_family])
    if pckg_alias not in recommended_packages:
        raise TestWarn(f"Package {pckg_alias} doesn't have recommended version")

    k8s_version = cluster.inventory['services']['kubeadm']['kubernetesVersion']
    expected_system_packages = pckgs.get_default_package_names(os_family, pckg_alias, k8s_version)

    good_results = set()
    bad_results = []
    actual_packages = cluster.get_package_association(pckg_alias, "package_name")
    if not isinstance(actual_packages, list):
        actual_packages = [actual_packages]
    for expected_pckg in expected_system_packages:
        expected_pckg_name = pckgs.get_package_name(os_family, expected_pckg)
        for actual_pckg in actual_packages:
            actual_pckg_name = pckgs.get_package_name(os_family, actual_pckg)
            if expected_pckg_name == actual_pckg_name:
                if actual_pckg.startswith(expected_pckg.replace("*", "")):
                    good_results.add(actual_pckg)
                else:
                    cluster.log.debug(f"Package {actual_pckg} is not recommended, recommended is {expected_pckg}")
                    bad_results.append(actual_pckg)

                break
        else:
            cluster.log.debug(f"Package {expected_pckg_name} is not found in inventory")
            bad_results.append(expected_pckg_name)

    if bad_results:
        raise TestWarn(f"Detected not recommended packages versions: {bad_results}")
    cluster.log.debug(f"Detected packages with recommended versions: {good_results}")


def system_packages_versions(cluster: KubernetesCluster, pckg_alias: str) -> None:
    """
    Verifies that system packages are installed on required nodes and have equal versions.
    Failure is shown if check is not successful.
    :param cluster: main cluster object.
    :param pckg_alias: system package alias to retrieve "package_name" association.
    """
    with TestCase(cluster, '205', "Services", f"{pckg_alias} version") as tc:
        _check_same_os(cluster)
        hosts_to_packages = pckgs.get_association_hosts_to_packages(cluster.nodes['all'], cluster.inventory, pckg_alias)
        if not hosts_to_packages:
            raise TestWarn(f"No nodes to check {pckg_alias!r} version")
        check_packages_versions(cluster, tc, hosts_to_packages, raise_successful=False)

        if pckg_alias in ["haproxy", "keepalived", "containerd", "docker"]:
            recommended_system_package_versions(cluster, pckg_alias)
        tc.success("all packages have correct versions")


def mandatory_packages_versions(cluster: KubernetesCluster) -> None:
    """
    Verifies that mandatory packages are installed on required nodes and have equal versions.
    Failure is shown if check is not successful.
    :param cluster: main cluster object.
    """
    with TestCase(cluster, '205', "Services", "Mandatory package versions") as tc:
        _check_same_os(cluster)
        hosts_to_packages: Dict[str, List[str]] = {}
        group = cluster.nodes['all']
        for package in cluster.inventory["services"]["packages"]['mandatory'].keys():
            packages = pckgs.get_association_hosts_to_packages(group, cluster.inventory, package)

            for host, packages_list in packages.items():
                hosts_to_packages.setdefault(host, []).extend(packages_list)

        if not hosts_to_packages:
            raise TestWarn(f"No mandatory packages to check")

        return check_packages_versions(cluster, tc, hosts_to_packages)


def generic_packages_versions(cluster: KubernetesCluster) -> None:
    """
    Verifies that user-provided packages are installed on required nodes and have equal versions.
    Warning is shown if check is not successful.
    """
    with TestCase(cluster, '206', "Services", f"Generic packages version") as tc:
        _check_same_os(cluster)
        packages = cluster.inventory['services']['packages'].get('install', {}).get('include', [])
        hosts_to_packages = {host: packages for host in cluster.nodes['all'].get_hosts()}
        return check_packages_versions(cluster, tc, hosts_to_packages, warn_on_bad_result=True)


def check_packages_versions(cluster: KubernetesCluster, tc: TestCase, hosts_to_packages: Dict[str, List[str]],
                            warn_on_bad_result: bool = False, raise_successful: bool = True) -> None:
    """
    Verifies that all packages are installed on required nodes and have equal versions
    :param cluster: main cluster object
    :param tc: current test case object
    :param hosts_to_packages: hosts where to check packages
    :param warn_on_bad_result: if true then uses Warning instead of Failure. Default False.
    """
    bad_results = []
    good_results = []

    packages_map = pckgs.detect_installed_packages_version_hosts(cluster, hosts_to_packages)
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
            package_name = package.replace("*", "")
            if version.startswith(package_name):
                good_results.append(version)
            else:
                bad_results.append(version)

    if bad_results:
        hint_message = f'Check the presence and correctness of the version of the following packages on the ' \
                       f'system: {bad_results}'
        if warn_on_bad_result:
            raise TestWarn("detected incorrect packages versions", hint=hint_message)
        raise TestFailure("detected incorrect packages versions", hint=hint_message)
    cluster.log.debug(f"installed packages: {good_results}")
    if raise_successful:
        tc.success("all packages have correct versions")


def get_nodes_description(cluster: KubernetesCluster) -> dict:
    return kubernetes.get_nodes_description(cluster)


def kubelet_version(cluster: KubernetesCluster) -> None:
    with TestCase(cluster, '203', "Services", "Kubelet Version",
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


def thirdparties_hashes(cluster: KubernetesCluster) -> None:
    """
    Task which is used to verify configured thirdparties hashes agains actual hashes on nodes.
    If thirdparty is an archive, then archive files hashes are also verified.
    If hash is not specified, then thirdparty is skipped.
    If there is no thirdparties with hashes, then warning is shown.
    """
    with TestCase(cluster, '212', "Thirdparties", "Hashes") as tc:
        successful = []
        warnings = []
        broken = []

        #Create tmp dir for loading thirdparty without default sha
        first_control_plane = cluster.nodes['control-plane'].get_first_member()
        first_control_plane_host = first_control_plane.get_host()

        for path, config in cluster.inventory['services']['thirdparties'].items():
            group = cluster.create_group_from_groups_nodes_names(config.get('groups', []), config.get('nodes', []))
            hosts_missing = find_hosts_missing_thirdparty(group, path)
            if hosts_missing:
                broken.append(f"thirdparty {path} is missing on {hosts_missing}")
                # if thirdparty is missing somewhere, do not check anything further for it
                continue

            is_curl = config['source'][:4] == 'http' and '://' in config['source'][4:8]
            expected_sha = None

            # Get sha from source, if it can be downloaded
            if is_curl:
                cluster.log.verbose(f"Thirdparty {path} doesn't have default sha, download it...")
                # Create tmp dir for loading thirdparty without default sha
                random_dir = "/tmp/%s" % uuid.uuid4().hex
                final_commands = "rm -r -f %s" % random_dir
                random_path = "%s%s" % (random_dir, path)
                cluster.log.verbose('Temporary path: %s' % random_path)
                remote_commands = "mkdir -p %s" % ('/'.join(random_path.split('/')[:-1]))
                # Load thirdparty to temporary dir
                remote_commands += "&& sudo curl -f -g -s --show-error -L %s -o %s" % (config['source'], random_path)
                results = first_control_plane.sudo(remote_commands, warn=True)
                if results.is_any_failed():
                    host = first_control_plane_host
                    msg = f"Can`t download thirdparty {path} on {host} for getting sha: {results[host].stderr}"
                    broken.append(msg)
                    cluster.log.verbose(msg)
                else:
                    # Get temporary thirdparty sha
                    cluster.log.verbose(f"Get temporary thirdparty sha for {path}...")
                    results = first_control_plane.sudo(f'openssl sha1 {random_path} | sed "s/^.* //"', warn=True)
                    if results.is_any_failed():
                        host = first_control_plane_host
                        msg = f'failed to get sha for temporary file {random_path} on {host}: {results[host].stderr}'
                        broken.append(msg)
                        cluster.log.verbose(msg)
                    else:
                        expected_sha = results.get_simple_out().strip()
                        cluster.log.verbose(f"Expected sha was got for {path}: {expected_sha}")
                # Remove temporary dir in any case
                cluster.log.verbose(f"Remove temporary dir {random_dir}...")
                first_control_plane.sudo(final_commands, warn=True)

            recommended_sha = thirdparties.get_thirdparty_recommended_sha(path, cluster)
            if recommended_sha is not None and recommended_sha != expected_sha:
                warnings.append(f"{path} source contains not recommended thirdparty version for used kubernetes version")

            if config.get("sha1", expected_sha) != expected_sha and expected_sha is not None:
                broken .append("Given sha is not equal with actual sha from source for %s" % path)

            expected_sha = config.get("sha1", expected_sha)

            if expected_sha is None:
                cluster.log.verbose(f"Can`t get expected sha for {path}, skip it")
                # Skip checking sha if something went wrong or this sha can't be loaded
                continue

            results = group.sudo(f'openssl sha1 {path} | sed "s/^.* //"', warn=True)
            actual_sha: Optional[str] = None
            first_host: Optional[str] = None
            # Searching actual SHA, if possible
            for host, result in results.items():
                if result.failed:
                    broken.append(f'failed to get {path} sha {host}: {result.stderr}')
                    continue

                found_sha = result.stdout.strip()
                if actual_sha is None:
                    actual_sha = found_sha
                    first_host = host
                elif actual_sha != found_sha:
                    broken.append(f'got inconsistent sha for {path}: {found_sha} on host {host}, '
                                  f'different from first host {first_host} sha {actual_sha}')
                    actual_sha = None
                    break

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
                extension = path.split('.')[-1]
                if extension == 'zip': 
                    res = group.sudo(' unzip -qq -l %s | awk \'NF > 3 { print $4 }\' | while read file_name; do '  # for each file in archive
                                 '  echo ${file_name} '  # print   1) filename
                                 '    $(sudo unzip -p %s ${file_name} | openssl sha1 | cut -d\\  -f2) '  # 2) sha archive
                                 '    $(sudo openssl sha1 %s/${file_name} | cut -d\\  -f2); '  # 3) sha unpacked
                                 'done' % (path, path, unpack_dir)) 
                else :
                    res = group.sudo('tar tf %s | grep -vw "./" | while read file_name; do '  # for each file in archive
                                 '  echo ${file_name} '  # print   1) filename
                                 '    $(sudo tar xfO %s ${file_name} | openssl sha1 | cut -d\\  -f2) '  # 2) sha archive
                                 '    $(sudo openssl sha1 %s/${file_name} | cut -d\\  -f2); '  # 3) sha unpacked
                                 'done' % (path, path, unpack_dir))
                
                # for each file on each host, verify that SHA in archive is equal to SHA for unpacked
                for host, result in res.items():
                    if result.failed:
                        broken.append(f'can not verify files SHA for archive {path} '
                                      f'on host {host}, unpacked to {unpack_dir}')
                        continue
                    files_results = result.stdout.strip().split('\n')
                    for file_result in files_results:
                        result_parts = file_result.split()
                        if len(result_parts) != 3:
                            broken.append(f'can not verify files SHA for archive {path} '
                                          f'on host {host}, unpacked to {unpack_dir}')
                            continue
                        filename, archive_hash, fs_hash = result_parts[0], result_parts[1], result_parts[2]
                        if archive_hash != fs_hash:
                            broken.append(f'hash for file {filename} from archive {path} '
                                          f'on host {host} is not equal to hash for file unpacked to {unpack_dir}')

        if broken:
            raise TestFailure('Found inconsistent hashes', hint=yaml.safe_dump(broken))
        if warnings:
            raise TestWarn('Found warnings', hint=yaml.safe_dump(warnings))
        tc.success('All found hashes are correct')


def find_hosts_missing_thirdparty(group: NodeGroup, path: str) -> List[str]:
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
            missing.append(host)
    return missing


def kubernetes_nodes_existence(cluster: KubernetesCluster) -> None:
    with TestCase(cluster, '209', "Kubernetes", "Nodes Existence",
                  default_results="All nodes presented"):
        nodes_description = get_nodes_description(cluster)
        nodes_names = kubernetes.get_actual_roles(nodes_description).keys()
        not_found = []
        for node in cluster.inventory['nodes']:
            if 'control-plane' in node['roles'] or 'worker' in node['roles']:
                if node['name'] in nodes_names:
                    cluster.log.debug("Node \"%s\" is found in cluster" % node['name'])
                else:
                    not_found.append(node['name'])
                    cluster.log.error("Node \"%s\" is not found in cluster" % node['name'])
        not_found = list(set(not_found))
        if not_found:
            raise TestFailure("Nodes not found: %s" % ', '.join(not_found),
                              hint="The cluster must contain all the nodes that are described in the inventory. Add "
                                   "the missing nodes to the cluster.")


def kubernetes_nodes_roles(cluster: KubernetesCluster) -> None:
    with TestCase(cluster, '210', "Kubernetes", "Nodes Roles",
                  default_results="All nodes have the correct roles"):
        nodes_description = get_nodes_description(cluster)
        nodes_roles = kubernetes.get_actual_roles(nodes_description)
        nodes_with_bad_roles = []
        for node_name, actual_roles in nodes_roles.items():
            node = cluster.get_node_by_name(node_name)
            if node is None:
                # TODO cluster has unexpected node. Need to add check to kubernetes.nodes.existence task.
                continue

            expected_roles = set(node['roles']).intersection({'control-plane', 'worker'})
            for expected_role in expected_roles:
                if expected_role not in actual_roles:
                    nodes_with_bad_roles.append(node_name)
                    cluster.log.error(f"Node \"{node_name}\" has to be {expected_role}, but has invalid role")
                else:
                    cluster.log.debug(f"Node \"{node_name}\" has correct {expected_role} role")

        nodes_with_bad_roles = list(set(nodes_with_bad_roles))
        if nodes_with_bad_roles:
            raise TestFailure("Incorrect role detected at: %s" % ', '.join(nodes_with_bad_roles),
                              hint="Some nodes whose role differs from that specified in the "
                                   "inventory were detected. The configuration of these nodes should be fixed.")


def kubernetes_nodes_condition(cluster: KubernetesCluster, condition_type: str) -> None:
    with TestCase(cluster, '211', "Kubernetes", "Nodes Condition - %s" % condition_type) as tc:
        nodes_description = get_nodes_description(cluster)
        expected_status = 'False'
        if condition_type == 'Ready':
            expected_status = 'True'
        positive_conditions = []
        negative_conditions = []
        nodes_conditions = kubernetes.get_nodes_conditions(nodes_description)
        for node_name, conditions_by_type in nodes_conditions.items():
            if condition_type in conditions_by_type:
                condition = conditions_by_type[condition_type]
                cluster.log.debug("Node \"%s\" condition \"%s\" is \"%s\""
                                  % (node_name, condition['type'], condition['reason']))
                if condition['status'] != expected_status:
                    negative_conditions.append(condition['reason'])
                else:
                    positive_conditions.append(condition['reason'])
            else:
                raise TestFailure("Failed to detect at %s" % node_name)

        negative_conditions = list(set(negative_conditions))
        positive_conditions = list(set(positive_conditions))

        if negative_conditions:
            raise TestFailure("%s" % ', '.join(negative_conditions),
                              hint="A condition in negative status means that there are problems with the health of "
                                   "the node.")

        tc.success(results="%s" % ', '.join(positive_conditions))


def get_not_running_pods(cluster: KubernetesCluster) -> str:
    # Completed pods should be excluded from the list as well
    get_pods_cmd = 'kubectl get pods -A --field-selector status.phase!=Running | awk \'{ print $1" "$2" "$4 }\' | grep -vw Completed || true'
    result = cluster.nodes['control-plane'].get_any_member().sudo(get_pods_cmd)
    cluster.log.verbose(result)
    return list(result.values())[0].stdout.strip()


def kubernetes_pods_condition(cluster: KubernetesCluster) -> None:
    system_namespaces = ["kube-system", "ingress-nginx", "kube-public", "kubernetes-dashboard", "default"]
    critical_states = cluster.globals['pods']['critical_states']
    with TestCase(cluster, '207', "Kubernetes", "Pods Condition") as tc:
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
                              hint="Try to determine the cause of the pods failure. Then redeploy, reapply, or restart them. If "
                                   "this is not fixed, the cluster may not work or may work incorrectly.")
        elif total_failed_amount > 0:
            s = ''
            if total_failed_amount != 1:
                s = 's'
            raise TestWarn("%s pod%s are failed/not running" % (total_failed_amount, s),
                           hint="Try to determine the reason the pods are not operational, "
                                "try to wait, redeploy, reapply, or restart them. "
                                "If this is not fixed, some deployed applications may not work or may work incorrectly.")
        else:
            tc.success(results="All pods are running")


def kubernetes_dashboard_status(cluster: KubernetesCluster) -> None:
    with TestCase(cluster, '208', "Plugins", "Dashboard Availability") as tc:
        retries = 10
        test_service_succeeded = False
        test_ingress_succeeded = False
        ingress_ip = cluster.inventory['control_plain']['internal']

        if not cluster.inventory['plugins']['kubernetes-dashboard']['install']:
            tc.success(results="skipped")
        else:
            # check dashboard service 
            cluster.log.debug('Check kubernetes-dashboard service...')
            i = 0
            while not test_service_succeeded and i < retries:
                i += 1
                results = cluster.nodes['control-plane'].get_first_member().sudo("kubectl get svc -n kubernetes-dashboard kubernetes-dashboard -o=jsonpath=\"{['spec.clusterIP']}\"", warn=True)
                for control_plane, result in results.items():
                    if result.failed:
                        cluster.log.debug(f'Can not get dashboard service IP: {result.stderr} ')
                        raise TestFailure("not available",hint=f"Please verify the following Kubernetes Dashboard status and fix this issue")
                found_url = result.stdout
                if ipaddress.ip_address(found_url).version == 4:
                    check_url = cluster.nodes['control-plane'].get_first_member().sudo(f'curl -k -I https://{found_url}:443', warn=True)
                else:
                    check_url = cluster.nodes['control-plane'].get_first_member().sudo(f'curl -g -k -I https://[{found_url}]:443', warn=True)
                status = list(check_url.values())[0].stdout
                if '200' in status:
                    cluster.log.debug(status)
                    test_service_succeeded = True
                else:
                    cluster.log.debug(f'Dashboard service is not running yet... Retries left: {retries - i}')
                    time.sleep(60)

            # check dashboard ingress
            cluster.log.debug('Check kubernetes-dashboard ingress...')
            i = 0
            while not test_ingress_succeeded and test_service_succeeded and i < retries:
                i += 1
                results = cluster.nodes['control-plane'].get_first_member().sudo("kubectl -n kubernetes-dashboard get ingress kubernetes-dashboard -o=jsonpath=\"{.spec.rules[0].host}\"", warn=True)
                for control_plane, result in results.items():
                    if result.failed:
                        cluster.log.debug(f'Can not get dashboard ingress hostname: {result.stderr} ')
                        raise TestFailure("not available",hint=f"Please verify the following Kubernetes Dashboard status and fix this issue")
                found_url = result.stdout
                
                if ipaddress.ip_address(ingress_ip).version == 4:
                    check_url = cluster.nodes['control-plane'].get_first_member().sudo(f'curl -k -I --resolve {found_url}:443:{ingress_ip} https://{found_url} 2>&1', warn=True)
                else:
                    check_url = cluster.nodes['control-plane'].get_first_member().sudo(f'curl -g -k -I --resolve "{found_url}:443:{ingress_ip}" https://{found_url} 2>&1', warn=True)
                status = list(check_url.values())[0].stdout
                if '200' in status:
                    cluster.log.debug(status)
                    test_ingress_succeeded = True
                else:
                    cluster.log.debug(f'Dashboard ingress is not running yet... Retries left: {retries - i}')
                    time.sleep(60)

            # test results
            if test_service_succeeded and test_ingress_succeeded:
                tc.success(results="available")
            else:
                raise TestFailure("not available",
                              hint=f"Please verify the following Kubernetes Dashboard status and fix this issue:\n{status}")


def kubernetes_audit_policy_configuration(cluster: KubernetesCluster) -> None:
    with TestCase(cluster, '229', "Kubernetes", "Audit policy configuration") as tc:
        expected_config = cluster.inventory['services']['audit'].get('cluster_policy')

        api_server_extra_args = cluster.inventory['services']['kubeadm']['apiServer']['extraArgs']
        audit_file_name = api_server_extra_args['audit-policy-file']

        control_planes = cluster.nodes['control-plane']

        broken = []
        result = control_planes.sudo(f"cat {audit_file_name}", warn=True)
        for node in control_planes.get_ordered_members_list():
            policy_result = result[node.get_host()]
            node_name = node.get_node_name()
            if policy_result.failed:
                broken.append(f"{node_name}: {audit_file_name} is absent")
            else:
                actual_config = yaml.safe_load(policy_result.stdout)
                diff = DeepDiff(actual_config, expected_config)
                if diff:
                    cluster.log.debug(f"Configuration of audit policy is not actual on {node_name} node")
                    # Extra transformation to JSON is necessary,
                    # because DeepDiff.to_dict() returns custom nested classes
                    # that cannot be serialized to yaml by default.
                    cluster.log.debug(yaml.safe_dump(yaml.safe_load(diff.to_json())))
                    broken.append(f"{node_name}: {audit_file_name} is not actual")

        if broken:
            broken.append(
                "Check DEBUG logs for details. "
                "To have the check passed, you may need to call `kubemarine install --tasks deploy.kubernetes.audit` "
                "or change the inventory file accordingly."
            )
            raise TestFailure('invalid', hint=yaml.safe_dump(broken))
        else:
            tc.success(results='valid')


def nodes_pid_max(cluster: KubernetesCluster) -> None:
    with TestCase(cluster, '202', "Nodes", "Nodes pid_max correctly installed") as tc:
        control_plane = cluster.nodes['control-plane'].get_any_member()
        yaml = ruamel.yaml.YAML()
        nodes_failed_pid_max_check = {}
        for node in cluster.make_group_from_roles(['control-plane', 'worker']).get_ordered_members_list():
            node_name = node.get_node_name()

            node_info = control_plane.sudo("kubectl get node %s -o yaml" % node_name).get_simple_out()
            config = yaml.load(node_info)
            max_pods = int(config['status']['capacity']['pods'])

            kubelet_config = node.sudo("cat /var/lib/kubelet/config.yaml").get_simple_out()
            config = yaml.load(kubelet_config)
            pod_pids_limit = int(config['podPidsLimit'])

            pid_max = int(node.sudo("cat /proc/sys/kernel/pid_max").get_simple_out())
            required_pid_max = max_pods * pod_pids_limit + 2048
            cluster.log.debug("Current values:\n maxPods = %s \n podPidsLimit = %s \n pid_max = %s"
                              % (max_pods, pod_pids_limit, pid_max))
            cluster.log.debug("Required pid_max for current kubelet configuration is %s for node '%s'"
                              % (required_pid_max, node_name))
            if cluster.inventory['services']['sysctl'].get("kernel.pid_max"):
                inventory_pid_max = cluster.inventory['services']['sysctl'].get("kernel.pid_max")
                if pid_max != inventory_pid_max:
                    raise TestWarn("The 'kernel.pid_max' value defined in system = %s, "
                                   "but 'kernel.pid_max', which defined in cluster.yaml = %s"
                                   % (pid_max, inventory_pid_max))
            if pid_max < required_pid_max:
                nodes_failed_pid_max_check[node_name] = [pid_max, required_pid_max]

        if nodes_failed_pid_max_check:
            output = "The requirement for the 'pid_max' value is not met for nodes:\n"
            for node_name in nodes_failed_pid_max_check:
                output += ("For node %s pid_max value = '%s', but it should be >= then '%s'\n"
                           % (node_name, nodes_failed_pid_max_check[node_name][0],
                              nodes_failed_pid_max_check[node_name][1]))
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
    if cluster.get_os_family() not in ('rhel', 'rhel8'):
        return

    with TestCase(cluster, '213', "Security", "Selinux security policy") as tc:
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
        for host, results in selinux_parsed_result.items():
            if results.get('status', '') != 'disabled':
                if results['mode'] == 'enforcing':
                    enforcing_ips.append(host)
                elif results['mode'] == 'permissive' and cluster.inventory.get('services', {})\
                        .get('kernel_security', {}).get('selinux', {}).get('state') == 'permissive':
                    permissive_ips.append(host)
                else:
                    bad_ips.append([host, results['mode']])
            else:
                bad_ips.append([host, 'disabled'])

        if group.nodes_amount() == len(enforcing_ips):
            tc.success(results='enforcing')
        elif len(bad_ips) == 0:
            pretty_list = '\n - ' + ('\n - '.join(permissive_ips))
            raise TestWarn('permissive',
                           hint=f"It is not recommended to use the permissive state, but this is possible if you "
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
                              hint=f"Selinux is configured with the wrong state, which is not recommended. Only "
                                   f"\"enforcing\" policy is recommended. Please use it on the following "
                                   f"nodes:{pretty_list}")


def verify_selinux_config(cluster: KubernetesCluster) -> None:
    """
    This method is a test, which compares the configuration of Selinux on the nodes with the configuration specified in
    the inventory or with the one by default. If the configuration does not match, the test will fail.
    :param cluster: KubernetesCluster object
    :return: None
    """
    if cluster.get_os_family() not in ('rhel', 'rhel8'):
        return

    with TestCase(cluster, '214', "Security", "Selinux configuration") as tc:
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
                                   f" using the installation procedure.")


def verify_firewalld_status(cluster: KubernetesCluster) -> None:
    """
    This method is a test, which verifies that the FirewallD is disabled on cluster nodes, otherwise the test will fail.
    :param cluster: KubernetesCluster object
    :return: None
    """
    with TestCase(cluster, '215', "Security", "Firewalld status") as tc:
        group = cluster.nodes['all']
        firewalld_disabled, firewalld_result = system.is_firewalld_disabled(group)
        cluster.log.debug(firewalld_result)
        if firewalld_disabled:
            tc.success(results='disabled')
        else:
            raise TestFailure('enabled',
                              hint=f"FirewallD must be disabled as it is not supported and can create compatibility "
                                   f"issues. To solve this problem, execute the firewalld disable task in the installation "
                                   f"procedure.")


def verify_time_sync(cluster: KubernetesCluster) -> None:
    """
    This method is a test that verifies that the time between all nodes does not lag behind.
    :param cluster: KubernetesCluster object
    :return: None
    """
    with TestCase(cluster, '218', "System", "Time difference") as tc:
        group = cluster.nodes['all']
        current_node_time, nodes_timestamp, time_diff = system.get_nodes_time(group)
        cluster.log.verbose('Current node time: %s' % current_node_time)
        cluster.log.verbose('Time difference: %s' % time_diff)
        cluster.log.verbose('Nodes time details:')
        for host, timestamp in nodes_timestamp.items():
            cluster.log.verbose(' - %s: %s' % (host, timestamp))

        if time_diff > cluster.globals['nodes']['max_time_difference']:
            raise TestWarn("%sms" % time_diff,
                           hint=f"The time difference between nodes is too large, this can lead to incorrect "
                                f"behavior of Kubernetes and services. To fix this problem, run the NTP configuring "
                                f"task on all nodes with the correct parameters. It is also worth paying attention to "
                                f"the delay between the deployed node and all the others - too much delay can lead to "
                                f"incorrect time measurements.")
        tc.success(results="%sms" % time_diff)


def verify_swap_state(cluster: KubernetesCluster) -> None:
    """
    This method is a test, which verifies that swap is disabled on all nodes in the cluster, otherwise the test will
    fail.
    :param cluster: KubernetesCluster object
    :return: None
    """
    with TestCase(cluster, '216', "System", "Swap state") as tc:
        group = cluster.nodes['all']
        swap_disabled, swap_result = system.is_swap_disabled(group)
        cluster.log.debug(swap_result)
        if swap_disabled:
            tc.success(results='disabled')
        else:
            raise TestFailure('enabled',
                              hint=f"Swap must be disabled as it is not supported and can create performance "
                                   f"issues. To solve this problem, execute the swap disable task in the installation "
                                   f"procedure.")


def verify_modprobe_rules(cluster: KubernetesCluster) -> None:
    """
    This method is a test, which compares the modprobe rules on the nodes with the rules specified in the inventory or
    with default rules. If rules does not match, the test will fail.
    :param cluster: KubernetesCluster object
    :return: None
    """
    with TestCase(cluster, '217', "System", "Modprobe rules") as tc:
        _check_same_os(cluster)
        group = cluster.nodes['all']
        modprobe_valid, modprobe_result = system.is_modprobe_valid(group)
        cluster.log.debug(modprobe_result)
        if modprobe_valid:
            tc.success(results='valid')
        else:
            raise TestFailure('invalid',
                              hint=f"Modprobe rules do not match those loaded in modprobe on cluster nodes. Check "
                                   f"manually what the differences are and make changes on the appropriate nodes.")


def etcd_health_status(cluster: KubernetesCluster) -> None:
    """
    This method is a test, check ETCD health
    :param cluster: KubernetesCluster object
    :return: None
    """
    with TestCase(cluster, '219', "ETCD", "Health status ETCD") as tc:
        try:
            etcd_health_status = etcd.wait_for_health(cluster, cluster.nodes['control-plane'].get_any_member())
        except Exception as e:
            cluster.log.verbose('Failed to load and parse ETCD status')
            raise TestFailure('invalid',
                              hint=f"ETCD not ready, please check"
                                   f" because of {e} ")
        cluster.log.debug(etcd_health_status)
        tc.success(results='healthy')


def container_runtime_configuration_check(cluster: KubernetesCluster) -> None:
    cri_impl: str = cluster.inventory['services']['cri']['containerRuntime']
    with TestCase(cluster, '204', "Services", f"{cri_impl.capitalize()} Configuration Check") as tc:
        if cluster.inventory['services']['cri']['containerRuntime'] != 'containerd':
            # Check for docker is not yet implemented
            return tc.success(results='valid')

        expected_config = containerd.get_config_as_toml(cluster.inventory['services']['cri']['containerdConfig'])
        expected_registries = {registry: containerd.get_config_as_toml(registry_conf)
                               for registry, registry_conf in
                               cluster.inventory['services']['cri'].get('containerdRegistriesConfig', {}).items()}
        kubernetes_nodes = cluster.make_group_from_roles(['control-plane', 'worker'])
        actual_configs, actual_registries = containerd.fetch_containerd_config(kubernetes_nodes)

        success = True
        for node in kubernetes_nodes.get_ordered_members_list():
            actual_config = actual_configs[node.get_host()]
            diff = DeepDiff(actual_config, expected_config)
            if diff:
                cluster.log.debug(f"Configuration of containerd is not actual on {node.get_node_name()} node")
                # Extra transformation to JSON is necessary,
                # because DeepDiff.to_dict() returns custom nested classes that cannot be serialized to yaml by default.
                cluster.log.debug(yaml.safe_dump(yaml.safe_load(diff.to_json())))
                success = False

            diff = DeepDiff(actual_registries.get(node.get_host(), {}), expected_registries)
            if diff:
                cluster.log.debug(f"Configuration of containerd registries is not actual on {node.get_node_name()} node")
                # Extra transformation to JSON is necessary,
                # because DeepDiff.to_dict() returns custom nested classes that cannot be serialized to yaml by default.
                cluster.log.debug(yaml.safe_dump(yaml.safe_load(diff.to_json())))
                success = False

        if not success:
            message = dedent(
                """\
                The configuration of the container runtime does not match
                the effectively resolved configuration from the inventory.
                Check DEBUG logs for details.
                To have the check passed, you may need to call
                `kubemarine install --tasks prepare.cri.configure`
                or change the inventory file accordingly.
                """.rstrip())
            raise TestFailure('invalid', hint=message)
        else:
            tc.success(results='valid')


def control_plane_configuration_status(cluster: KubernetesCluster) -> None:
    '''
    This test verifies the consistency of the configuration (image version, `extra_args`, `extra_volumes`) of static pods of Control Plain like `kube-apiserver`, `kube-controller-manager` and `kube-scheduler`
    :param cluster: KubernetesCluster object
    :return: None
    '''
    with TestCase(cluster, '220', "Control plane", "configuration status") as tc:
        results: List[dict] = []
        static_pod_names = {'kube-apiserver': 'apiServer',
                            'kube-controller-manager': 'controllerManager',
                            'kube-scheduler': 'scheduler'}
        static_pods_content = []
        not_presented_static_pods = []
        for control_plane in cluster.nodes['control-plane'].get_ordered_members_list():
            for static_pod_name, value in static_pod_names.items():
                static_pod_result = control_plane.sudo(f'cat /etc/kubernetes/manifests/{static_pod_name}.yaml', warn=True)
                exit_code = list(static_pod_result.values())[0].exited
                if exit_code == 0:
                    static_pod = yaml.safe_load(static_pod_result.get_simple_out())
                    static_pod[static_pod_name] = value
                    static_pods_content.append(static_pod)
                else:
                    not_presented_static_pods.append(static_pod_name)
            for not_presented_static_pod in not_presented_static_pods:
                del static_pod_names[not_presented_static_pod]

            result: dict = {'name': control_plane.get_node_name()}
            version = cluster.inventory["services"]["kubeadm"]["kubernetesVersion"]

            node_config = control_plane.get_config()
            for static_pod in static_pods_content:
                result[static_pod['metadata']['name']] = {}
                result[static_pod['metadata']['name']]['correct_version'] = \
                    version in static_pod["spec"]["containers"][0].get("image", "")
                result[static_pod['metadata']['name']]['correct_properties'] = \
                    check_extra_args(cluster, static_pod, node_config)
                result[static_pod['metadata']['name']]['correct_volumes'] = check_extra_volumes(cluster, static_pod)
            results.append(result)

        message = ""
        for result in results:
            for static_pod_name in static_pod_names:
                if result[static_pod_name]['correct_version'] and \
                   result[static_pod_name]['correct_properties'] and \
                   result[static_pod_name]['correct_volumes']:
                    cluster.log.verbose(f'Control-plane {result["name"]} has correct configuration for {static_pod_name}')
                else:
                    message += f"Control-plane {result['name']} has incorrect configuration for {static_pod_name} \n"
        if not_presented_static_pods:
            message += f"{not_presented_static_pods} static pods doesn't presented"

        if not message:
            tc.success(results='valid')
        else:
            raise TestFailure('invalid', hint=message)


def check_extra_args(cluster: KubernetesCluster, static_pod: dict, node: NodeConfig) -> bool:
    static_pod_name = static_pod[static_pod['metadata']['name']]
    for arg, value in cluster.inventory["services"]["kubeadm"][static_pod_name].get("extraArgs", {}).items():
        if arg == "bind-address":
            # for "bind-address" we do not take default value into account, because its patched to node internal-address
            value = node["internal_address"]
        correct_property = False
        original_property = arg + "=" + value
        properties = static_pod["spec"]["containers"][0].get("command", [])
        for property in properties:
            if original_property in property:
                correct_property = True
                break
        if not correct_property:
            return False
    return True


def check_extra_volumes(cluster: KubernetesCluster, static_pod: dict) -> bool:
    static_pod_name = static_pod[static_pod['metadata']['name']]
    #for original_volume in cluster.inventory["services"]["kubeadm"][static_pod_name].get("extraVolumes", {}).items():
    for original_volume in cluster.inventory["services"]["kubeadm"][static_pod_name].get("extraVolumes", {}):
        correct_volume = False
        volume_mounts = static_pod["spec"]["containers"][0].get("volumeMounts", {})
        for volumeMount in volume_mounts:
            if volumeMount['mountPath'] == original_volume['mountPath'] and \
                    volumeMount['name'] == original_volume['name'] and \
                    volumeMount.get('readOnly', False ) == original_volume.get('readOnly', False):
                correct_volume = True
                break
        if not correct_volume:
            return False

        correct_volume = False

        volumes = static_pod["spec"].get("volumes", [])
        for volume in volumes:
            if volume['name'] == original_volume['name'] and \
                    volume['hostPath']['path'] == original_volume['hostPath'] and \
                    volume['hostPath']['type'] == original_volume['pathType']:
                correct_volume = True
                break
        if not correct_volume:
            return False
    return True


def control_plane_health_status(cluster: KubernetesCluster) -> None:
    '''
    This test verifies the health of static pods `kube-apiserver`, `kube-controller-manager` and `kube-scheduler`
    :param cluster: KubernetesCluster object
    :return: None
    '''
    with TestCase(cluster, '221', "Control plane", "health status") as tc:
        static_pods = ['kube-apiserver', 'kube-controller-manager', 'kube-scheduler']
        static_pod_names = []

        for control_plane in cluster.nodes['control-plane'].get_ordered_members_list():
            for static_pod in static_pods:
                static_pod_names.append(static_pod + '-' + control_plane.get_node_name())

        first_control_plane = cluster.nodes['control-plane'].get_first_member()
        not_found_pod = []
        for static_pod_name in static_pod_names:
            results = first_control_plane.sudo(f"kubectl get pod -n kube-system -oyaml {static_pod_name}", warn=True)
            exit_code = list(results.values())[0].exited
            if exit_code == 0:
                result = yaml.safe_load(results.get_simple_out())
                if result['status']['containerStatuses'][0]['state'].get('running'):
                    break
            not_found_pod.append(static_pod_name)

        if len(not_found_pod) == 0:
            tc.success(results='valid')
        else:
            raise TestFailure('invalid', hint=f"{not_found_pod} pods doesn't running")


def default_services_configuration_status(cluster: KubernetesCluster) -> None:
    '''
    In this test, the versions of the images of the default services, such as `kube-proxy`, `coredns`,
    `calico-node`, `calico-kube-controllers`, `calico-apiserver` and `ingress-nginx-controller`, are checked,
    and the `coredns` configmap is also checked.

    :param cluster: KubernetesCluster object
    :return: None
    '''
    with TestCase(cluster, '222', "Default services", "configuration status") as tc:
        first_control_plane = cluster.nodes['control-plane'].get_first_member()
        original_coredns_cm = yaml.safe_load(generate_configmap(cluster.inventory))
        result = first_control_plane.sudo('kubectl get cm coredns -n kube-system -oyaml')
        coredns_cm = yaml.safe_load(result.get_simple_out())
        ddiff = DeepDiff(coredns_cm['data'], original_coredns_cm['data'], ignore_order=True)
        coredns_result = ddiff.to_dict().get('values_changed', {}).get("root['Corefile']", {}).get('diff')

        message = ""
        if coredns_result:
            message += f"CoreDNS config is outdated: \n {coredns_result} \n"

        coredns_version = first_control_plane.sudo("kubeadm config images list | grep coredns").get_simple_out().split(":")[1].rstrip()
        version = cluster.inventory['services']['kubeadm']['kubernetesVersion']
        calico_version = cluster.globals["compatibility_map"]["software"]["calico"][version]["version"]
        nginx_ingress_version = cluster.globals["compatibility_map"]["software"]["nginx-ingress-controller"][version]["version"]
        entities_to_check = {"kube-system": [{"DaemonSet": [{"calico-node": {"version": calico_version}},
                                                            {"kube-proxy": {"version": version}}]},
                                             {"Deployment": [{"calico-kube-controllers": {"version": calico_version}},
                                                             {"coredns": {"version": coredns_version}}]}],
                             "ingress-nginx": [{"DaemonSet": [{"ingress-nginx-controller": {"version": nginx_ingress_version}}]}]}
        if calico.is_apiserver_enabled(cluster.inventory):
            entities_to_check['calico-apiserver'] = [{"Deployment": [{"calico-apiserver": {"version": calico_version}}]}]

        for namespace, types_dict in entities_to_check.items():
            for type_dict in types_dict:
                for type, services in type_dict.items():
                    for service in services:
                        for service_name, properties in service.items():
                            if service_name == "ingress-nginx-controller":
                                if not cluster.inventory['plugins']['nginx-ingress-controller']['install']:
                                    break
                            k8s_object = KubernetesObject(cluster, type, service_name, namespace)
                            k8s_object.reload(control_plane=first_control_plane, suppress_exceptions=True)
                            if not k8s_object.is_reloaded():
                                message += f"failed to load {service_name}: {k8s_object}\n"
                                continue

                            if properties["version"] not in k8s_object.obj["spec"]["template"]["spec"]["containers"][0].get("image", ""):
                                message += f"{service_name} has outdated image version\n"

        if message:
            raise TestFailure('invalid', hint=f"{message}")
        else:
            tc.success(results='valid')


def default_services_health_status(cluster: KubernetesCluster) -> None:
    '''
    This test verifies the health of pods `kube-proxy`, `coredns`,
    `calico-node`, `calico-kube-controllers`, `calico-apiserver` and `ingress-nginx-controller`.

    :param cluster: KubernetesCluster object
    :return: None
    '''
    with TestCase(cluster, '223', "Default services", "health status") as tc:
        entities_to_check = {"kube-system": [{"DaemonSet": ["calico-node", "kube-proxy"]},
                                             {"Deployment": ["calico-kube-controllers", "coredns"]}],
                             "ingress-nginx": [{"DaemonSet": ["ingress-nginx-controller"]}]}
        if calico.is_apiserver_enabled(cluster.inventory):
            entities_to_check['calico-apiserver'] = [{"Deployment": ["calico-apiserver"]}]

        first_control_plane = cluster.nodes['control-plane'].get_first_member()
        not_ready_entities = []
        for namespace, types_dict in entities_to_check.items():
            for type_dict in types_dict:
                for type, services in type_dict.items():
                    if type == 'DaemonSet':
                        for service in services:
                            if service == "ingress-nginx-controller":
                                if not cluster.inventory['plugins']['nginx-ingress-controller']['install']:
                                    break
                            daemon_set = DaemonSet(cluster, name=service, namespace=namespace)
                            ready = daemon_set.reload(control_plane=first_control_plane, suppress_exceptions=True).is_actual_and_ready()
                            if not ready:
                                not_ready_entities.append(service)
                    elif type == 'Deployment':
                        for service in services:
                            deployment = Deployment(cluster, name=service, namespace=namespace)
                            ready = deployment.reload(control_plane=first_control_plane, suppress_exceptions=True).is_actual_and_ready()
                            if not ready:
                                not_ready_entities.append(service)
        if len(not_ready_entities) == 0:
            tc.success(results='valid')
        else:
            raise TestFailure('invalid', hint=f"{not_ready_entities} pods doesn't ready")


def calico_config_check(cluster: KubernetesCluster) -> None:
    '''
    This test checks the configuration of the `calico-node` envs, Calico's ConfigMap in case of `ipam`, and also performed `calicoctl ipam check`.
    :param cluster: KubernetesCluster object
    :return: None
    '''
    with TestCase(cluster, '224', "Calico", "configuration check") as tc:
        message = ""
        correct_config = True
        first_control_plane = cluster.nodes['control-plane'].get_first_member()
        result = first_control_plane.sudo(f"kubectl get DaemonSet calico-node -n kube-system -oyaml")
        calico_daemonset = yaml.safe_load(result.get_simple_out())
        for env in calico_daemonset["spec"]["template"]["spec"]["containers"][0]["env"]:
            if cluster.inventory["plugins"]["calico"]["env"].get(env["name"]):
                if "value" in env.keys() and not str(cluster.inventory["plugins"]["calico"]["env"].get(env["name"])) == env["value"]:
                    correct_config = False
                if "valueFrom" in env.keys() and len(DeepDiff(cluster.inventory["plugins"]["calico"]["env"].get(env["name"]), env["valueFrom"], ignore_order=True)) != 0:
                    correct_config = False
        if not correct_config:
            message += "calico-node env configuration is outdated\n"

        result = first_control_plane.sudo(f"kubectl get cm calico-config -n kube-system -oyaml")
        calico_config = yaml.safe_load(result.get_simple_out())
        cni_network_config = yaml.safe_load(calico_config["data"]["cni_network_config"])
        ip = cluster.inventory['services']['kubeadm']['networking']['podSubnet'].split('/')[0]
        if type(ipaddress.ip_address(ip)) is ipaddress.IPv4Address:
            ipam_config = cluster.inventory["plugins"]["calico"]["cni"]["ipam"]["ipv4"]
        else:
            ipam_config = cluster.inventory["plugins"]["calico"]["cni"]["ipam"]["ipv6"]
        ddiff = DeepDiff(ipam_config, cni_network_config["plugins"][0]["ipam"], ignore_order=True)
        if ddiff:
            message += f"calico cm is outdated: {ddiff.to_dict()}\n"

        result = first_control_plane.sudo("calicoctl ipam check | grep 'found .* problems' |  tr -dc '0-9'")
        found_problems = result.get_simple_result()
        if 'Version mismatch' in found_problems.stderr:
            version_mismatch_lines = found_problems.stderr.split('\n')

            def calico_version(criteria: str) -> str:
                return next(map(lambda l: l.split()[-1],
                                filter(lambda l: criteria in l,
                                       version_mismatch_lines),
                                ),
                            'unknown')

            client_version = calico_version('Client Version')
            cluster_version = calico_version('Cluster Version')
            message += f"client version {client_version} mismatches the cluster version {cluster_version}"
        elif int(found_problems.stdout) > 0:
            message += "ipam check indicates some problems," \
                       " for more info you can use `calicoctl ipam check --show-problem-ips`"
        if message:
            raise TestFailure('invalid', hint=message)
        else:
            tc.success(results='valid')


def calico_apiserver_health_status(cluster: KubernetesCluster) -> None:
    """
    This test verifies the Calico API server health.

    :param cluster: KubernetesCluster object
    :return: None
    """
    with TestCase(cluster, '230', "Calico", "API server health status") as tc:
        if not calico.is_apiserver_enabled(cluster.inventory):
            return tc.success(results='disabled')

        control_planes = cluster.nodes["control-plane"]
        with kubernetes.local_admin_config(control_planes) as kubeconfig:
            result = control_planes.sudo(f"kubectl --kubeconfig {kubeconfig} get ippools.projectcalico.org", warn=True)

        if result.is_any_failed():
            message = "Calico API server is not ready:\n"
            for host in result.get_failed_hosts_list():
                stderr = result[host].stderr
                if stderr:
                    message += f"{host}: {stderr}"
            raise TestFailure('invalid', hint=message)
        else:
            tc.success(results='valid')


def kubernetes_admission_status(cluster: KubernetesCluster) -> None:
    """
    The method checks status of Pod Security Admissions, default Pod Security Profile,
    and 'kube-apiserver.yaml' and 'kubeadm-config' consistancy
    """
    with TestCase(cluster, '225', "Kubernetes", "Pod Security Admissions") as tc:
        first_control_plane = cluster.nodes['control-plane'].get_first_member()
        profile_inv = ""
        if cluster.inventory["rbac"]["admission"] == "pss" and \
                cluster.inventory["rbac"]["pss"]["pod-security"] == "enabled":
            profile_inv = cluster.inventory["rbac"]["pss"]["defaults"]["enforce"]
        profile = ""
        result = first_control_plane.sudo("kubectl get cm kubeadm-config -n kube-system -o yaml")
        kubeadm_cm = yaml.safe_load(list(result.values())[0].stdout)
        cluster_config = yaml.safe_load(kubeadm_cm["data"]["ClusterConfiguration"])
        api_result = first_control_plane.sudo("cat /etc/kubernetes/manifests/kube-apiserver.yaml")
        api_conf = yaml.safe_load(list(api_result.values())[0].stdout)
        ext_args = [cmd for cmd in api_conf["spec"]["containers"][0]["command"]]
        admission_path = ""
        minor_version = int(cluster.inventory['services']['kubeadm']['kubernetesVersion'].split('.')[1])
        for item in ext_args:
            if item.startswith("--"):
                key = item.split('=')[0]
                value = item[len(key) + 1:]
                if key == "--admission-control-config-file":
                    admission_path = value
                    adm_result = first_control_plane.sudo("cat %s" % admission_path)
                    adm_conf = yaml.safe_load(list(adm_result.values())[0].stdout)
                    profile = adm_conf["plugins"][0]["configuration"]["defaults"]["enforce"]
                    if minor_version >= 28:
                        kube_admission_status = 'PSS is "enabled", default profile is "%s"' % profile
                        cluster.log.debug(kube_admission_status)
                        tc.success(results='enabled')
                if key == "--feature-gates":
                    features = value
                    if "PodSecurity=false" not in features:
                        kube_admission_status = 'PSS is "enabled", default profile is "%s"' % profile
                        cluster.log.debug(kube_admission_status)
                        tc.success(results='enabled')
                        feature_cm = cluster_config["apiServer"]["extraArgs"].get("feature-gates", "")
                        if features != feature_cm:
                            raise TestWarn('enable',
                                    hint=f"Check if the '--feature-gates' option in 'kubeadm-config' "
                                         f"is consistent with 'kube-apiserver.yaml")
                        admission_path_cm = cluster_config["apiServer"]["extraArgs"].get("admission-control-config-file","")
                        if admission_path != admission_path_cm:
                            raise TestWarn('enable',
                                    hint=f"Check if the '--admission-control-config-file' option in 'kubeadm-config' "
                                         f"is consistent with 'kube-apiserver.yaml")
                    else:
                        kube_admission_status = 'PSS is "disabled"'
                        cluster.log.debug(kube_admission_status)
                        tc.success(results='disabled')
        if profile != profile_inv:
            raise TestFailure('invalid',
                    hint=f"The 'cluster.yaml' does not match with the configuration "
                         f"that is applied on cluster in 'kube-apiserver.yaml' and 'admission.yaml'")
        if not profile:
            kube_admission_status = 'PSS is "disabled"'
            cluster.log.debug(kube_admission_status)
            tc.success(results='disabled')


def geo_check(cluster: KubernetesCluster) -> None:
    """
    This test checks connectivity between clusters in geo schemas using paas-geo-monitor service.
    This test only work if "procedure.yaml" has "geo-monitor" section filled.
    """
    if not cluster.procedure_inventory or not cluster.procedure_inventory.get("geo-monitor"):
        cluster.log.debug("Geo connectivity check is skipped, no configuration provided")
        return

    status_collected = False
    dns_status: Dict[str, List[str]] = {"failed": []}
    svc_status: Dict[str, List[str]] = {"failed": [], "skipped": []}
    pod_status: Dict[str, List[str]] = {"failed": [], "skipped": []}

    # Here we actually collect information about all statuses, but report information about DNS only.
    # Other statuses are reported in other TestCases below. This is done for better UX.
    with TestCase(cluster, '226', "Geo Monitor", "Geo check - DNS resolving") as tc_dns:
        geo_monitor_inventory = cluster.procedure_inventory["geo-monitor"]
        namespace = geo_monitor_inventory["namespace"]
        service = geo_monitor_inventory["service"]
        control_plane_node = cluster.nodes['control-plane'].get_first_member()

        svc_result = control_plane_node.sudo("kubectl get svc -n %s %s -o yaml" % (namespace, service)).get_simple_out()
        svc = yaml.safe_load(io.StringIO(svc_result))
        ip = svc["spec"]["clusterIP"]
        port = svc["spec"]["ports"][0]["port"]

        # todo: support https?
        status_cmd = f'curl http://{ip}:{port}/peers/status'
        if ipaddress.ip_address(ip).version == 6:
            status_cmd += " -g"
        peers_result = cluster.nodes['control-plane'].get_first_member().\
            sudo(f'curl http://{ip}:{port}/peers/status').get_simple_out()

        peers = yaml.safe_load(io.StringIO(peers_result))
        if len(peers) == 0:
            raise TestFailure("configuration error", hint="geo-monitor instance has no peers")

        for peer in peers:
            status = peer["clusterIpStatus"]
            if not status["dnsStatus"]["resolved"]:
                error = f'FAILED DNS resolving for peer ({peer["name"]}) service ' \
                        f'name: {status["name"]}, error: {status["dnsStatus"]["error"]}'
                dns_status["failed"].append(error)
                svc_status["skipped"].append(error)
                pod_status["skipped"].append(error)
                continue
            if not status["svcStatus"]["available"]:
                error = f'FAILED ping service for peer ({peer["name"]}), ' \
                        f'address: {status["svcStatus"]["address"]}, error: {status["svcStatus"]["error"]}'
                svc_status["failed"].append(error)
                pod_status["skipped"].append(error)
                continue
            if not status["podStatus"]["available"]:
                error = f'FAILED ping pod for peer ({peer["name"]}), ' \
                        f'address: {status["podStatus"]["address"]}, error: {status["podStatus"]["error"]}'
                pod_status["failed"].append(error)
                continue

        status_collected = True
        if dns_status["failed"]:
            raise TestFailure("found failed DNS statuses", hint=yaml.safe_dump(dns_status["failed"]))
        tc_dns.success("all peer names resolved")

    with TestCase(cluster, '226', "Geo Monitor", "Geo check - Pod-to-service") as tc_svc:
        if not status_collected:
            raise TestFailure("configuration error", hint="DNS check failed with error, statuses not collected")

        if svc_status["failed"]:
            raise TestFailure("found unavailable peer services",
                              hint=yaml.safe_dump(svc_status["failed"] + svc_status["skipped"]))
        if svc_status["skipped"]:
            raise TestWarn("found skipped peer services", hint=yaml.safe_dump(svc_status["skipped"]))
        tc_svc.success("all peer services available")

    with TestCase(cluster, '226', "Geo Monitor", "Geo check - Pod-to-pod") as tc_pod:
        if not status_collected:
            raise TestFailure("configuration error", hint="DNS check failed with error, statuses not collected")

        if pod_status["failed"]:
            raise TestFailure("found unavailable peer pod",
                              hint=yaml.safe_dump(pod_status["failed"] + pod_status["skipped"]))
        if pod_status["skipped"]:
            raise TestWarn("found skipped peer pods", hint=yaml.safe_dump(pod_status["skipped"]))
        tc_pod.success("all peer pods available")


def verify_apparmor_status(cluster: KubernetesCluster) -> None:
    """
    This method is a test, which checks the status of Apparmor.
    This test is applicable only for systems of the Debian family.
    :param cluster: KubernetesCluster object
    :return: None
    """
    if cluster.get_os_family() in ['rhel', 'rhel8']:
        return

    with TestCase(cluster, '227', "Security", "Apparmor security policy") as tc:
        group = cluster.nodes['all'].get_accessible_nodes()
        results = group.sudo("aa-enabled")
        enabled_nodes: List[str] = []
        invalid_nodes: List[str] = []
        for host, item in results.items():
            apparmor_status = item.stdout
            cluster.log.warning(f"Apparmor on node: {host} enabled: {apparmor_status}")
            if apparmor_status ==  "Yes":
                enabled_nodes.append(host)
            else:
                enabled_nodes.append(host)
        if group.nodes_amount() == len(enabled_nodes):
            tc.success(results='enabled')
        else:
            raise TestFailure(f"Apparmor does not properly configured on the following nodes: {invalid_nodes}")


def verify_apparmor_config(cluster: KubernetesCluster) -> None:
    """
    This method tests if the Apparmor configuration matches to 'cluster.yaml' spec.
    This test is applicable only for systems of the Debian family.
    :param cluster: KubernetesCluster object
    :return: None
    """
    if cluster.get_os_family() in ['rhel', 'rhel8']:
        return

    with TestCase(cluster, '228', "Security", "Apparmor security policy") as tc:
        expected_profiles = cluster.inventory['services']['kernel_security'].get('apparmor', {})
        group = cluster.nodes['all'].get_accessible_nodes()
        if expected_profiles:
            apparmor_configured = apparmor.is_state_valid(group, expected_profiles)
            if apparmor_configured:
                cluster.log.verbose(f"Apparmor is configured properly on cluster")
                tc.success(results='valid')
            else:
                raise TestFailure('invalid',
                        hint=f"Some nodes do not have properly configured Apparmor service")
        else:
            tc.success(results='skipped')


tasks = OrderedDict({
    'services': {
        'security': {
            'selinux': {
                'status': verify_selinux_status,
                'config': verify_selinux_config
            },
            'apparmor': {
                'status': verify_apparmor_status,
                'config': verify_apparmor_config
            },
            'firewalld': {
                'status': verify_firewalld_status
            }
        },
        'system': {
            'time': verify_time_sync,
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
            'configuration': container_runtime_configuration_check,
        },
        'kubelet': {
            'status': lambda cluster: services_status(cluster, 'kubelet'),
            'configuration': lambda cluster: nodes_pid_max(cluster),
            'version': kubelet_version,
        },
        'packages': {
            'system': {
                'cri_version': lambda cluster:
                    system_packages_versions(cluster, cluster.inventory['services']['cri'][ 'containerRuntime']),
                'haproxy_version': lambda cluster: system_packages_versions(cluster, 'haproxy'),
                'keepalived_version': lambda cluster: system_packages_versions(cluster, 'keepalived'),
                'audit_version': lambda cluster: system_packages_versions(cluster, 'audit'),
                'mandatory_versions': mandatory_packages_versions
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
        'audit': {
            'policy': kubernetes_audit_policy_configuration,
        },
        'admission': kubernetes_admission_status,
    },
    'etcd': {
        "health_status": etcd_health_status
    },
    'control_plane': {
        "configuration_status": control_plane_configuration_status,
        "health_status": control_plane_health_status
    },
    'default_services': {
        "configuration_status": default_services_configuration_status,
        "health_status": default_services_health_status
    },
    'calico': {
        "config_check": calico_config_check,
        "apiserver": {
            "health_status": calico_apiserver_health_status,
        }
    },
    'geo_check': geo_check,
})


class PaasAction(Action):
    def __init__(self) -> None:
        super().__init__('check paas')

    def run(self, res: DynamicResources) -> None:
        flow.run_tasks(res, tasks)


def create_context(cli_arguments: List[str] = None) -> dict:
    cli_help = '''
    Script for checking Kubernetes cluster PAAS layer.
    
    Hot to use:

    '''

    parser = flow.new_procedure_parser(cli_help, optional_config=True, tasks=tasks)

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

    context = flow.create_context(parser, cli_arguments, procedure='check_paas')
    context['testsuite'] = TestSuite()
    context['preserve_inventory'] = False

    return context


def main(cli_arguments: List[str] = None) -> TestSuite:
    context = create_context(cli_arguments)
    flow_ = flow.ActionsFlow([PaasAction()])
    result = flow_.run_flow(context, print_summary=False)

    context = result.context
    testsuite: TestSuite = context['testsuite']

    # Final summary should be printed only to stdout with custom formatting
    # If tests results required for parsing, they can be found in test results files
    print(testsuite.get_final_summary(show_minimal=False, show_recommended=False))
    testsuite.print_final_status(result.logger)
    check_iaas.make_reports(context)
    return testsuite


if __name__ == '__main__':
    testsuite = main()
    if testsuite.is_any_test_failed():
        sys.exit(1)
