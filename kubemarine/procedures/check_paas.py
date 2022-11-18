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


import sys
import time
from collections import OrderedDict
import re
from typing import List

import yaml
import ruamel.yaml
import ipaddress
import uuid

from kubemarine import packages as pckgs, system, selinux, etcd, thirdparties
from kubemarine.core.action import Action
from kubemarine.core.cluster import KubernetesCluster
from kubemarine.core.resources import DynamicResources
from kubemarine.procedures import check_iaas
from kubemarine.core import flow
from kubemarine.testsuite import TestSuite, TestCase, TestFailure, TestWarn
from kubemarine.kubernetes.daemonset import DaemonSet
from kubemarine.kubernetes.deployment import Deployment
from kubemarine.coredns import generate_configmap
from deepdiff import DeepDiff

# Global variable for 'Maintenance mode'
mntc_mode = False

def services_status(cluster, service_type):
    global mntc_mode
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
            group = cluster.nodes['control-plane'].include_group(cluster.nodes.get('worker'))

        if not group or group.is_empty():
            raise TestWarn("No nodes to check service status",
                           hint="The node group to check the service is empty. Check skipped.")

        result = group.sudo('systemctl status %s' % service_name, warn=True)
        cluster.log.verbose(result)

        status_regexp = re.compile("Active:\s([a-z\s()]*)(\ssince|$)", re.M)

        statuses = []
        failed = False
        mntc_list = []
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
            # Check if HAproxy is running in Maintenance mode
            if service_type == 'haproxy' and \
                    cluster.inventory['services']['loadbalancer']['haproxy'].get('maintenance_mode', False):
                mntc_config_location = group.cluster.inventory['services']['loadbalancer']['haproxy']['mntc_config_location']
                is_mntc = re.findall(mntc_config_location, node_result.stdout)
                if is_mntc:
                    cluster.log.warning("%s balancer is running in the maintenance mode" % connection.host)
                    mntc_list.append(connection.host)

        # Check if Kubernetes API is disable in maintenance mode
        if service_type == 'haproxy' and \
                    cluster.inventory['services']['loadbalancer']['haproxy'].get('maintenance_mode', False):
            kuber_ip_disable = False
            kuber_ip = cluster.inventory['public_cluster_ip']
            for item in cluster.inventory['vrrp_ips']:
                if kuber_ip == item['ip'] and \
                        item.get('params', {}).get('maintenance-type', '') == 'not bind':
                    kuber_ip_disable = True
            if kuber_ip_disable and len(group.get_nodes_names()) == len(mntc_list):
                mntc_mode = True
                raise TestWarn("Kubernetes API unavailable due to HAProxy maintenance mode")

        statuses = list(set(statuses))

        if failed:
            raise TestFailure("Bad status detected: %s" % ', '.join(statuses),
                              hint="Fix the service to be enabled and has running status.")


def recommended_system_packages_versions(cluster):
    """
    Task that checks if configured "system" packages versions are compatible with the configured k8s version and OS.
    Fails if unable to detect the OS family.
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
        containerd_name = "containerd"
        containerd_name_last = "containerd"
        if "docker" in cluster.inventory['services']['cri']['containerRuntime']:
            if version_key == "version_rhel":
                containerd_name = "containerd.io"
                containerd_name_last = "containerdio"

            expected_system_packages["docker"] = {
                "docker": compatibility["docker"][k8s_version][version_key],
                containerd_name: compatibility[containerd_name_last][k8s_version][version_key]
                }
        elif "containerd" in cluster.inventory["services"]["cri"]["containerRuntime"]:
            if version_key in ["version_rhel", "version_rhel8"]:
                containerd_name = "containerd.io"
                containerd_name_last = "containerdio"

            expected_system_packages["containerd"] = {
                containerd_name: compatibility[containerd_name_last][k8s_version][version_key],
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
                           hint=f'Check the list of recommended packages and what is listed in the inventory and fix '
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
            group = cluster.nodes['control-plane'].include_group(cluster.nodes.get('worker'))
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
    result = cluster.nodes['control-plane'].get_any_member().sudo('kubectl get node -o yaml')
    cluster.log.verbose(result)
    return yaml.safe_load(list(result.values())[0].stdout)


def kubelet_version(cluster):
    with TestCase(cluster.context['testsuite'], '203', "Services", "Kubelet Version",
                  default_results=cluster.inventory['services']['kubeadm']['kubernetesVersion']):
        if mntc_mode:
            raise TestWarn("Current check is skipped due to Kubernetes API is unreachable in maintenance mode")
            return
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
        warnings = []
        broken = []

        #Create tmp dir for loading thirdparty without default sha
        first_control_plane = cluster.nodes['control-plane'].get_first_member()

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
                results = first_control_plane.sudo(remote_commands, hide=True, warn=True)
                host, result = list(results.items())[0]
                if result.failed:
                    broken.append(f"Can`t download thirdparty {path} on {host.host} for getting sha: {result.stderr}")
                    cluster.log.verbose(f"Can`t download thirdparty {path} on {host.host} for getting sha: {result.stderr}")
                else:
                    # Get temporary thirdparty sha
                    cluster.log.verbose(f"Get temporary thirdparty sha for {path}...")
                    results = first_control_plane.sudo(f'openssl sha1 {random_path} | sed "s/^.* //"', warn=True)
                    host, result = list(results.items())[0]
                    if result.failed:
                        broken.append(f'failed to get sha for temporary file {random_path} on {host.host}: {result.stderr}')
                        cluster.log.verbose(f'failed to get sha for temporary file {random_path} on {host.host}: {result.stderr}')
                    else:
                        expected_sha = result.stdout.strip()
                        cluster.log.verbose(f"Expected sha was got for {path}: {expected_sha}")
                # Remove temporary dir in any case
                cluster.log.verbose(f"Remove temporary dir {random_dir}...")
                first_control_plane.sudo(final_commands, hide=True, warn=True)

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
                # for each file on each host, verify that SHA in archive is equal to SHA for unpacked
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
        if warnings:
            raise TestWarn('Found warnings', hint=yaml.safe_dump(warnings))
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
        if mntc_mode:
            raise TestWarn("Current check is skipped due to Kubernetes API is unreachable in maintenance mode")
            return
        nodes_description = get_nodes_description(cluster)
        not_found = []
        for node in cluster.inventory['nodes']:
            if 'control-plane' in node['roles'] or 'worker' in node['roles']:
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
                                   "the missing nodes to the cluster.")


def kubernetes_nodes_roles(cluster):
    with TestCase(cluster.context['testsuite'], '210', "Kubernetes", "Nodes Roles",
                  default_results="All nodes have the correct roles"):
        if mntc_mode:
            raise TestWarn("Current check is skipped due to Kubernetes API is unreachable in maintenance mode")
            return
        nodes_description = get_nodes_description(cluster)
        nodes_with_bad_roles = []
        for node in cluster.inventory['nodes']:
            for node_description in nodes_description['items']:
                node_name = node_description['metadata']['name']
                if node['name'] == node_name:
                    if 'control-plane' in node['roles']:
                        # TODO check label accordingly to Kubernetes version
                        if 'node-role.kubernetes.io/master' not in node_description['metadata']['labels'] and \
                           'node-role.kubernetes.io/control-plane' not in node_description['metadata']['labels']:
                            nodes_with_bad_roles.append(node['name'])
                            cluster.log.error("Node \"%s\" has to be control-plane, but has invalid role" % node['name'])
                        else:
                            cluster.log.debug("Node \"%s\" has correct control-plane role" % node['name'])
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
                              hint="Some nodes whose role differs from that specified in the "
                                   "inventory were detected. The configuration of these nodes should be fixed.")


def kubernetes_nodes_condition(cluster, condition_type):
    with TestCase(cluster.context['testsuite'], '211', "Kubernetes", "Nodes Condition - %s" % condition_type) as tc:
        if mntc_mode:
            raise TestWarn("Current check is skipped due to Kubernetes API is unreachable in maintenance mode")
            return
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
    # Completed pods should be excluded from the list as well
    get_pods_cmd = 'kubectl get pods -A --field-selector status.phase!=Running | awk \'{ print $1" "$2" "$4 }\' | grep -vw Completed || true'
    result = cluster.nodes['control-plane'].get_any_member().sudo(get_pods_cmd)
    cluster.log.verbose(result)
    return list(result.values())[0].stdout.strip()


def kubernetes_pods_condition(cluster):
    system_namespaces = ["kube-system", "ingress-nginx", "kube-public", "kubernetes-dashboard", "default"]
    critical_states = cluster.globals['pods']['critical_states']
    with TestCase(cluster.context['testsuite'], '207', "Kubernetes", "Pods Condition") as tc:
        if mntc_mode:
            raise TestWarn("Current check is skipped due to Kubernetes API is unreachable in maintenance mode")
            return
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


def kubernetes_dashboard_status(cluster):
    with TestCase(cluster.context['testsuite'], '208', "Plugins", "Dashboard Availability") as tc:
        if mntc_mode:
            raise TestWarn("Current check is skipped due to Kubernetes API is unreachable in maintenance mode")
            return
        retries = 10
        test_succeeded = False
        i = 0
        while not test_succeeded and i < retries:
            i += 1
            if cluster.inventory['plugins']['kubernetes-dashboard']['install']:
                results = cluster.nodes['control-plane'].get_first_member().sudo("kubectl get svc -n kubernetes-dashboard kubernetes-dashboard -o=jsonpath=\"{['spec.clusterIP']}\"", warn=True)
                for control_plane, result in results.items():
                    if result.failed:
                       cluster.log.debug(f'Can not resolve dashboard IP: {result.stderr} ')
                       raise TestFailure("not available",hint=f"Please verify the following Kubernetes Dashboard status and fix this issue")
                found_url = result.stdout
                if ipaddress.ip_address(found_url).version == 4:
                    check_url = cluster.nodes['control-plane'].get_first_member().sudo(f'curl -k -I https://{found_url}:443', warn=True)
                else:
                    check_url = cluster.nodes['control-plane'].get_first_member().sudo(f'curl -g -k -I https://[{found_url}]:443', warn=True)
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
        if mntc_mode:
            raise TestWarn("Current check is skipped due to Kubernetes API is unreachable in maintenance mode")
            return
        control_plane = cluster.nodes['control-plane'].get_any_member()
        yaml = ruamel.yaml.YAML()
        nodes_failed_pid_max_check = {}
        for node in cluster.nodes['control-plane'].include_group(cluster.nodes.get('worker')).get_ordered_members_list(provide_node_configs=True):

            node_info = control_plane.sudo("kubectl get node %s -o yaml" % node["name"]).get_simple_out()
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
            if results.get('status', '') != 'disabled':
                if results['mode'] == 'enforcing':
                    enforcing_ips.append(conn.host)
                elif results['mode'] == 'permissive' and cluster.inventory.get('services', {})\
                        .get('kernel_security', {}).get('selinux', {}).get('state') == 'permissive':
                    permissive_ips.append(conn.host)
                else:
                    bad_ips.append([conn.host, results['mode']])
            else:
                bad_ips.append([conn.host, 'disabled'])

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
                                   f" using the installation procedure.")


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
                                   f"issues. To solve this problem, execute the firewalld disable task in the installation "
                                   f"procedure.")


def verify_time_sync(cluster: KubernetesCluster) -> None:
    """
    This method is a test that verifies that the time between all nodes does not lag behind.
    :param cluster: KubernetesCluster object
    :return: None
    """
    with TestCase(cluster.context['testsuite'], '218', "System", "Time difference") as tc:
        group = cluster.nodes['all']
        current_node_time, nodes_timestamp, time_diff = system.get_nodes_time(group)
        cluster.log.verbose('Current node time: %s' % current_node_time)
        cluster.log.verbose('Time difference: %s' % time_diff)
        cluster.log.verbose('Nodes time details:')
        for host, timestamp in nodes_timestamp.items():
            cluster.log.verbose(' - %s: %s' % (host.host, timestamp))

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
    with TestCase(cluster.context['testsuite'], '216', "System", "Swap state") as tc:
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
    :param cluster: KubernetesCluster object
    :return: None
    """
    with TestCase(cluster.context['testsuite'], '219', "ETCD", "Health status ETCD") as tc:
        try:
            etcd_health_status = etcd.wait_for_health(cluster, cluster.nodes['control-plane'].get_any_member())
        except Exception as e:
            cluster.log.verbose('Failed to load and parse ETCD status')
            raise TestFailure('invalid',
                              hint=f"ETCD not ready, please check"
                                   f" because of {e} ")
        cluster.log.debug(etcd_health_status)
        tc.success(results='healthy')


def control_plane_configuration_status(cluster):
    '''
    This test verifies the consistency of the configuration (image version, `extra_args`, `extra_volumes`) of static pods of Control Plain like `kube-apiserver`, `kube-controller-manager` and `kube-scheduler`
    :param cluster: KubernetesCluster object
    :return: None
    '''
    with TestCase(cluster.context['testsuite'], '220', "Control plane", "configuration status") as tc:
        if mntc_mode:
            raise TestWarn("Current check is skipped due to Kubernetes API is unreachable in maintenance mode")
            return
        results = []
        static_pod_names = {'kube-apiserver': 'apiServer',
                            'kube-controller-manager': 'controllerManager',
                            'kube-scheduler': 'scheduler'}
        static_pods_content = []
        not_presented_static_pods = []
        for control_plane in cluster.nodes['control-plane'].get_ordered_members_list(provide_node_configs=True):
            for static_pod_name, value in static_pod_names.items():
                result = control_plane['connection'].sudo(f'cat /etc/kubernetes/manifests/{static_pod_name}.yaml', warn=True)
                exit_code = list(result.values())[0].exited
                result = result.get_simple_out()
                if exit_code == 0:
                    result = yaml.safe_load(result)
                    result[static_pod_name] = value
                    static_pods_content.append(result)
                else:
                    not_presented_static_pods.append(static_pod_name)
            for not_presented_static_pod in not_presented_static_pods:
                del static_pod_names[not_presented_static_pod]

            result = dict()
            result['name'] = control_plane['name']
            version = cluster.inventory["services"]["kubeadm"]["kubernetesVersion"]

            for static_pod in static_pods_content:
                result[static_pod['metadata']['name']] = dict()
                if version in static_pod["spec"]["containers"][0].get("image", ""):
                    result[static_pod['metadata']['name']]['correct_version'] = True
                result[static_pod['metadata']['name']]['correct_properties'] = \
                    check_extra_args(cluster, static_pod, control_plane)
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


def check_extra_args(cluster, static_pod, node):
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


def check_extra_volumes(cluster, static_pod):
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


def control_plane_health_status(cluster):
    '''
    This test verifies the health of static pods `kube-apiserver`, `kube-controller-manager` and `kube-scheduler`
    :param cluster: KubernetesCluster object
    :return: None
    '''
    with TestCase(cluster.context['testsuite'], '221', "Control plane", "health status") as tc:
        if mntc_mode:
            raise TestWarn("Current check is skipped due to Kubernetes API is unreachable in maintenance mode")
            return
        static_pods = ['kube-apiserver', 'kube-controller-manager', 'kube-scheduler']
        static_pod_names = []

        for control_plane in cluster.nodes['control-plane'].get_ordered_members_list(provide_node_configs=True):
            for static_pod in static_pods:
                static_pod_names.append(static_pod + '-' + control_plane['name'])

        first_control_plane = cluster.nodes['control-plane'].get_first_member()
        not_found_pod = []
        for static_pod_name in static_pod_names:
            result = first_control_plane.sudo(f"kubectl get pod -n kube-system -oyaml {static_pod_name}", warn=True)
            exit_code = list(result.values())[0].exited
            if exit_code == 0:
                result = result.get_simple_out()
                result = yaml.safe_load(result)
                if result['status']['containerStatuses'][0]['state'].get('running'):
                    break
            not_found_pod.append(static_pod_name)

        if len(not_found_pod) == 0:
            tc.success(results='valid')
        else:
            raise TestFailure('invalid', hint=f"{not_found_pod} pods doesn't running")


def default_services_configuration_status(cluster):
    '''
    In this test, the versions of the images of the default services, such as `kube-proxy`, `coredns`, `calico-node`, `calico-kube-controllers` and `ingress-nginx-controller`, are checked, and the `coredns` configmap is also checked.
    :param cluster: KubernetesCluster object
    :return: None
    '''
    with TestCase(cluster.context['testsuite'], '222', "Default services", "configuration status") as tc:
        if mntc_mode:
            raise TestWarn("Current check is skipped due to Kubernetes API is unreachable in maintenance mode")
            return
        first_control_plane = cluster.nodes['control-plane'].get_first_member()
        original_coredns_cm = generate_configmap(cluster.inventory)
        original_coredns_cm = yaml.safe_load(original_coredns_cm)
        coredns_cm = first_control_plane.sudo('kubectl get cm coredns -n kube-system -oyaml').get_simple_out()
        coredns_cm = yaml.safe_load(coredns_cm)
        ddiff = DeepDiff(coredns_cm['data'], original_coredns_cm['data'], ignore_order=True)
        coredns_result = ddiff.to_dict().get('values_changed', {}).get("root['Corefile']", {}).get('diff')

        message = ""
        if coredns_result:
            message += f"CoreDNS config is outdated: \n {coredns_result} \n"

        coredns_version = first_control_plane.sudo("kubeadm config images list | grep coredns").get_simple_out().split(":")[1].rstrip()
        version = ".".join(cluster.inventory['services']['kubeadm']['kubernetesVersion'].split('.')[0:2])
        entities_to_check = {"kube-system": [{"DaemonSet": [{"calico-node": {"version": cluster.globals["compatibility_map"]["software"]["calico"][version]["version"]}},
                                                            {"kube-proxy": {"version": cluster.inventory["services"]["kubeadm"]["kubernetesVersion"]}}]},
                                             {"Deployment": [{"calico-kube-controllers": {"version": cluster.globals["compatibility_map"]["software"]["calico"][version]["version"]}},
                                                             {"coredns": {"version": coredns_version}}]}],
                             "ingress-nginx": [{"DaemonSet": [{"ingress-nginx-controller": {"version": cluster.globals["compatibility_map"]["software"]["nginx-ingress-controller"][version]["version"]}}]}]}

        results = dict()
        for namespace, types_dict in entities_to_check.items():
            for type_dict in types_dict:
                for type, services in type_dict.items():
                    for service in services:
                        for service_name, properties in service.items():
                            if service_name == "ingress-nginx-controller":
                                if not cluster.inventory['plugins']['nginx-ingress-controller']['install']:
                                    break
                            content = first_control_plane.sudo(f"kubectl get {type} {service_name} -n {namespace} -oyaml").get_simple_out()
                            content = yaml.safe_load(content)
                            if properties["version"] in content["spec"]["template"]["spec"]["containers"][0].get("image", ""):
                                results[service_name] = True
                            else:
                                results[service_name] = False
        for item, condition in results.items():
            if not condition:
                message += f"{item} has outdated image version\n"

        if message:
            raise TestFailure('invalid', hint=f"{message}")
        else:
            tc.success(results='valid')


def default_services_health_status(cluster):
    '''
    This test verifies the health of pods `kube-proxy`, `coredns`, `calico-node`, `calico-kube-controllers` and `ingress-nginx-controller`.
    :param cluster: KubernetesCluster object
    :return: None
    '''
    with TestCase(cluster.context['testsuite'], '223', "Default services", "health status") as tc:
        if mntc_mode:
            raise TestWarn("Current check is skipped due to Kubernetes API is unreachable in maintenance mode")
            return
        entities_to_check = {"kube-system": [{"DaemonSet": ["calico-node", "kube-proxy"]},
                                             {"Deployment": ["calico-kube-controllers", "coredns"]}],
                             "ingress-nginx": [{"DaemonSet": ["ingress-nginx-controller"]}]}

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


def calico_config_check(cluster):
    '''
    This test checks the configuration of the `calico-node` envs, Calico's ConfigMap in case of `ipam`, and also performed `calicoctl ipam check`.
    :param cluster: KubernetesCluster object
    :return: None
    '''
    with TestCase(cluster.context['testsuite'], '224', "Calico", "configuration check") as tc:
        if mntc_mode:
            raise TestWarn("Current check is skipped due to Kubernetes API is unreachable in maintenance mode")
            return
        message = ""
        correct_config = True
        first_control_plane = cluster.nodes['control-plane'].get_first_member()
        result = first_control_plane.sudo(f"kubectl get DaemonSet calico-node -n kube-system -oyaml")
        result = result.get_simple_out()
        result = yaml.safe_load(result)
        for env in result["spec"]["template"]["spec"]["containers"][0]["env"]:
            if cluster.inventory["plugins"]["calico"]["env"].get(env["name"]):
                if not str(cluster.inventory["plugins"]["calico"]["env"].get(env["name"])) == env["value"]:
                    correct_config = False
        if not correct_config:
            message += "calico-node env configuration is outdated\n"

        result = first_control_plane.sudo(f"kubectl get cm calico-config -n kube-system -oyaml").get_simple_out()
        result = yaml.safe_load(result)
        result = yaml.safe_load(result["data"]["cni_network_config"])
        if isinstance(cluster.inventory["services"]["kubeadm"]["networking"]["podSubnet"], ipaddress.IPv4Address):
            ipam_config = cluster.inventory["plugins"]["calico"]["cni"]["ipam"]["ipv4"]
        else:
            ipam_config = cluster.inventory["plugins"]["calico"]["cni"]["ipam"]["ipv6"]
        ddiff = DeepDiff(ipam_config, result["plugins"][0]["ipam"], ignore_order=True)
        ipam_diff = ddiff.to_dict().get('values_changed', {}).get("root['Corefile']", {}).get('diff')
        if ipam_diff:
            message += f"calico cm is outdated: {ipam_diff}\n"

        result = first_control_plane.sudo("calicoctl ipam check | grep 'found .* problems' |  tr -dc '0-9'").get_simple_out()
        if int(result) > 0:
            message += "ipam check indicates some problems," \
                       " for more info you can use `calicoctl ipam check --show-problem-ips`"
        if message:
            raise TestFailure('invalid', hint=message)
        else:
            tc.success(results='valid')

def kubernetes_admission_status(cluster):
    """
    The method checks status of Pod Security Admissions, default Pod Security Profile,
    and 'kube-apiserver.yaml' and 'kubeadm-config' consistancy
    """
    with TestCase(cluster.context['testsuite'], '225', "Kubernetes", "Pod Security Admissions") as tc:
        if mntc_mode:
            raise TestWarn("Current check is skipped due to Kubernetes API is unreachable in maintenance mode")
            return
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
        for item in ext_args:
            if item.startswith("--"):
                key = re.split('=',item)[0]
                value = re.search('=(.*)$', item).group(1)
                if key == "--admission-control-config-file":
                    admission_path = value
                    adm_result = first_control_plane.sudo("cat %s" % admission_path)
                    adm_conf = yaml.safe_load(list(adm_result.values())[0].stdout)
                    profile = adm_conf["plugins"][0]["configuration"]["defaults"]["enforce"]
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
        "config_check": calico_config_check
    }
})


class PaasAction(Action):
    def __init__(self):
        super().__init__('check paas')

    def run(self, res: DynamicResources):
        flow.run_tasks(res, tasks)


def main(cli_arguments=None):
    cli_help = '''
    Script for checking Kubernetes cluster PAAS layer.
    
    Hot to use:

    '''

    parser = flow.new_tasks_flow_parser(cli_help)

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

    context = flow.create_context(parser, cli_arguments, procedure='paas')
    context['testsuite'] = TestSuite()
    context['preserve_inventory'] = False

    cluster = flow.run_actions(context, [PaasAction()], print_final_message=False)

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
