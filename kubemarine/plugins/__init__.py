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

import glob
import importlib.util
import io
import os
import re
import shutil
import ssl
import subprocess
import sys
import tarfile
import time
import urllib.request
import zipfile
from copy import deepcopy
from distutils.dir_util import copy_tree
from distutils.dir_util import remove_tree
from distutils.dir_util import mkpath
from itertools import chain
from typing import Dict, List, Tuple

import yaml

from kubemarine.core.cluster import KubernetesCluster
from kubemarine import jinja, thirdparties
from kubemarine.core import utils, static
from kubemarine.core.yaml_merger import default_merger
from kubemarine.core.group import NodeGroup, NodeGroupResult
from kubemarine.kubernetes.daemonset import DaemonSet
from kubemarine.kubernetes.deployment import Deployment
from kubemarine.kubernetes.replicaset import ReplicaSet
from kubemarine.kubernetes.statefulset import StatefulSet

# list of plugins owned and managed by kubemarine
oob_plugins = list(static.DEFAULTS["plugins"].keys())


def verify_inventory(inventory, cluster):
    for plugin_name, plugin_item in inventory["plugins"].items():
        for step in plugin_item.get('installation', {}).get('procedures', []):
            for procedure_type, configs in step.items():
                if procedure_types[procedure_type].get('verify') is not None:
                    procedure_types[procedure_type]['verify'](cluster, configs)

    return inventory


def enrich_inventory(inventory, cluster):
    for plugin_name, plugin_item in inventory["plugins"].items():
        for i, step in enumerate(plugin_item.get('installation', {}).get('procedures', [])):
            for procedure_type, configs in step.items():
                if procedure_types[procedure_type].get('convert') is not None:
                    step[procedure_type] = procedure_types[procedure_type]['convert'](cluster, configs)
    return inventory


def enrich_upgrade_inventory(inventory, cluster):
    if cluster.context.get("initial_procedure") != "upgrade":
        return inventory

    base_plugins = static.DEFAULTS["plugins"]
    current_plugins = deepcopy(inventory["plugins"])

    # validate all plugin sections in procedure inventory
    upgrade_plan = cluster.procedure_inventory.get('upgrade_plan')
    previous_version = cluster.context['initial_kubernetes_version']
    for version in upgrade_plan:
        upgrade_plugins = cluster.procedure_inventory.get(version, {}).get("plugins", {})
        for oob_plugin in oob_plugins:
            verify_image_redefined(oob_plugin,
                                   previous_version,
                                   base_plugins[oob_plugin],
                                   current_plugins[oob_plugin],
                                   upgrade_plugins.get(oob_plugin, {}))
        default_merger.merge(current_plugins, upgrade_plugins)
        previous_version = version

    upgrade_plugins = cluster.procedure_inventory.get(cluster.context["upgrade_version"], {}).get("plugins", {})
    default_merger.merge(inventory["plugins"], upgrade_plugins)
    return inventory


def verify_image_redefined(plugin_name, previous_version, base_plugin, cluster_plugin, upgrade_plugin):
    """
    If some image in "cluster_plugin" is different from image in "base_plugin",
    i.e. redefined, then "upgrade_plugin" should have this image explicitly
    redefined too.
    """
    for key, value in base_plugin.items():
        if isinstance(value, dict):
            verify_image_redefined(plugin_name,
                                   previous_version,
                                   base_plugin[key],
                                   cluster_plugin[key],
                                   upgrade_plugin.get(key, {}))
        elif key == "image" and base_plugin["image"] != cluster_plugin["image"] and not upgrade_plugin.get("image"):
            raise Exception(f"Image is redefined for {plugin_name} in cluster.yaml for version {previous_version}, "
                            f"but not present in procedure inventory for next version(s). "
                            f"Please, specify required plugin version explicitly in procedure inventory.")


def install(cluster, plugins=None):
    if not plugins:
        plugins = cluster.inventory["plugins"]
    plugins_queue: List[str] = []
    max_priority = 0
    for plugin_name, plugin_item in plugins.items():
        if plugin_item.get("install", False) and plugin_item.get("installation", {}).get('procedures') is not None:
            plugins_queue.append(plugin_name)
            if plugin_item.get("installation", {}).get('priority') is not None \
                    and plugin_item['installation']['priority'] > max_priority:
                max_priority = plugin_item['installation']['priority']

    plugins_queue.sort(key=lambda name: plugins[name].get("installation", {}).get('priority', max_priority + 1))

    cluster.log.debug('The following plugins will be installed:')
    for plugin_name in plugins_queue:
        cluster.log.debug('%i. %s' % (
            plugins[plugin_name].get("installation", {}).get('priority', max_priority + 1),
            plugin_name
        ))

    cluster.log.debug('Starting plugins installation:')

    for plugin_name in plugins_queue:
        install_plugin(cluster, plugin_name, plugins[plugin_name]["installation"]['procedures'])


def install_plugin(cluster, plugin_name, installation_procedure):
    cluster.log.debug("**** INSTALLING PLUGIN %s ****" % plugin_name)

    for current_step_i, step in enumerate(installation_procedure):
        for apply_type, configs in step.items():
            procedure_types[apply_type]['apply'](cluster, configs, plugin_name)


def expect_daemonset(cluster: KubernetesCluster,
                     daemonsets_names: List[str] or List[Dict[str, str]],
                     timeout: int = None,
                     retries: int = None,
                     node: NodeGroup = None) -> None:
    """
    The method waits for the configuration parameters of the given DaemonSets to be applied.
    :param cluster: KubernetesCluster object where method should be performed
    :param daemonsets_names: List of DaemonSet names (or dicts with name and namespace) to be
    expected
    :param timeout: Retry attempt time (seconds)
    :param retries: Number of retry attempts
    :param node: Node where daemonsets should be detected
    :return: None
    """

    log = cluster.log

    if timeout is None:
        timeout = cluster.globals['expect']['plugins']['timeout']
    if retries is None:
        retries = cluster.globals['expect']['plugins']['retries']

    log.debug(f"Expecting the following DaemonSets to be up to date: {daemonsets_names}")
    log.verbose("Max expectation time: %ss" % (timeout * retries))

    log.debug("Waiting for DaemonSets...")

    daemonsets = []
    for name in daemonsets_names:
        if isinstance(name, str):
            daemonsets.append(DaemonSet(cluster, name=name, namespace='kube-system'))
        elif isinstance(name, dict):
            daemonsets.append(DaemonSet(cluster, name=name['name'], namespace=name['namespace']))

    while retries > 0:
        up_to_date = True
        for daemonset in daemonsets:
            if not daemonset.reload(control_plane=node, suppress_exceptions=True).is_up_to_date():
                up_to_date = False

        if up_to_date:
            cluster.log.debug("DaemonSets are up to date")
            return
        else:
            retries -= 1
            cluster.log.debug(f"DaemonSets are not up to date yet... ({retries * timeout}s left)")
            time.sleep(timeout)

    raise Exception('In the expected time, the DaemonSets did not become ready')


def expect_replicaset(cluster: KubernetesCluster,
                      replicasets_names: List[str] or List[Dict[str, str]],
                      timeout: int = None,
                      retries: int = None,
                      node: NodeGroup = None) -> None:
    """
    The method waits for the configuration parameters of the given ReplicaSets to be applied.
    :param cluster: KubernetesCluster object where method should be performed
    :param replicasets_names: List of ReplicaSets names (or dicts with name and namespace) to be
    expected
    :param timeout: Retry attempt time (seconds)
    :param retries: Number of retry attempts
    :param node: Node where replicasests should be detected
    :return: None
    """

    log = cluster.log

    if timeout is None:
        timeout = cluster.globals['expect']['plugins']['timeout']
    if retries is None:
        retries = cluster.globals['expect']['plugins']['retries']

    log.debug(f"Expecting the following ReplicaSets to be up to date: {replicasets_names}")
    log.verbose("Max expectation time: %ss" % (timeout * retries))

    log.debug("Waiting for ReplicaSets...")

    replicasets = []
    for name in replicasets_names:
        if isinstance(name, str):
            replicasets.append(ReplicaSet(cluster, name=name, namespace='kube-system'))
        elif isinstance(name, dict):
            replicasets.append(ReplicaSet(cluster, name=name['name'], namespace=name['namespace']))

    while retries > 0:
        up_to_date = True
        for replicaset in replicasets:
            if not replicaset.reload(control_plane=node, suppress_exceptions=True).is_available():
                up_to_date = False

        if up_to_date:
            cluster.log.debug("ReplicaSets are up to date")
            return
        else:
            retries -= 1
            cluster.log.debug(f"ReplicaSets are not up to date yet... ({retries * timeout}s left)")
            time.sleep(timeout)

    raise Exception('In the expected time, the ReplicaSets did not become ready')


def expect_statefulset(cluster: KubernetesCluster,
                       statefulsets_names: List[str] or List[Dict[str, str]],
                       timeout: int = None,
                       retries: int = None,
                       node: NodeGroup = None) -> None:
    """
    The method waits for the configuration parameters of the given StatefulSets to be applied.
    :param cluster: KubernetesCluster object where method should be performed
    :param statefulsets_names: List of StatefulSets names (or dicts with name and namespace) to be
    expected
    :param timeout: Retry attempt time (seconds)
    :param retries: Number of retry attempts
    :param node: Node where statefulsets should be detected
    :return: None
    """

    log = cluster.log

    if timeout is None:
        timeout = cluster.globals['expect']['plugins']['timeout']
    if retries is None:
        retries = cluster.globals['expect']['plugins']['retries']

    log.debug(f"Expecting the following StatefulSets to be up to date: {statefulsets_names}")
    log.verbose("Max expectation time: %ss" % (timeout * retries))

    log.debug("Waiting for StatefulSets...")

    statefulsets = []
    for name in statefulsets_names:
        if isinstance(name, str):
            statefulsets.append(StatefulSet(cluster, name=name, namespace='kube-system'))
        elif isinstance(name, dict):
            statefulsets.append(StatefulSet(cluster, name=name['name'], namespace=name['namespace']))

    while retries > 0:
        up_to_date = True
        for statefulset in statefulsets:
            if not statefulset.reload(control_plane=node, suppress_exceptions=True).is_updated():
                up_to_date = False

        if up_to_date:
            cluster.log.debug("StatefulSets are up to date")
            return
        else:
            retries -= 1
            cluster.log.debug(f"StatefulSets are not up to date yet... ({retries * timeout}s left)")
            time.sleep(timeout)

    raise Exception('In the expected time, the StatefulSets did not become ready')


def expect_deployment(cluster: KubernetesCluster,
                      deployments_names: List[str] or List[Dict[str, str]],
                      timeout: int = None,
                      retries: int = None,
                      node: NodeGroup = None):
    """
    The method waits for the configuration parameters of the given Deployments to be applied.
    :param cluster: KubernetesCluster object where method should be performed
    :param deployments_names: List of Deployments names (or dicts with name and namespace) to be
    expected
    :param timeout: Retry attempt time (seconds)
    :param retries: Number of retry attempts
    :param node: Node where deployments should be detected
    :return: None
    """

    log = cluster.log

    if timeout is None:
        timeout = cluster.globals['expect']['plugins']['timeout']
    if retries is None:
        retries = cluster.globals['expect']['plugins']['retries']

    log.debug(f"Expecting the following Deployments to be up to date: {deployments_names}")
    log.verbose("Max expectation time: %ss" % (timeout * retries))

    log.debug("Waiting for Deployments...")

    deployments = []
    for name in deployments_names:
        if isinstance(name, str):
            deployments.append(Deployment(cluster, name=name, namespace='kube-system'))
        elif isinstance(name, dict):
            deployments.append(Deployment(cluster, name=name['name'], namespace=name['namespace']))

    while retries > 0:
        up_to_date = True
        for deployment in deployments:
            if not deployment.reload(control_plane=node, suppress_exceptions=True).is_actual_and_ready():
                up_to_date = False

        if up_to_date:
            cluster.log.debug("Deployments are up to date!")
            return
        else:
            retries -= 1
            cluster.log.debug(f"Deployments are not up to date yet... ({retries * timeout}s left)")
            time.sleep(timeout)

    raise Exception('In the expected time, the Deployments did not become ready')


def expect_pods(cluster, pods, namespace=None, timeout=None, retries=None,
                node=None, apply_filter=None):

    if isinstance(cluster, NodeGroup):
        # when instead of cluster there was received a group
        cluster = cluster.cluster

    if timeout is None:
        timeout = cluster.globals['expect']['plugins']['timeout']
    if retries is None:
        retries = cluster.globals['expect']['plugins']['retries']

    cluster.log.debug("Expecting the following pods to be ready: %s" % pods)
    cluster.log.verbose("Max expectation time: %ss" % (timeout * retries))

    cluster.log.debug("Waiting for pods...")

    failures = 0

    if node is None:
        node = cluster.nodes['control-plane'].get_first_member()

    namespace_filter = '-A'
    if namespace is not None:
        namespace_filter = "-n " + namespace

    command = f"kubectl get pods {namespace_filter} -o=wide"
    if apply_filter is not None:
        command += ' | grep %s' % apply_filter

    while retries > 0:

        result = node.sudo(command, warn=True)

        stdout = list(result.values())[0].stdout
        running_pods_stdout = ''

        failure_found = False

        for stdout_line in iter(stdout.splitlines()):

            stdout_line_allowed = False

            # is current line has requested pod for verification?
            # we do not have to fail on pods with bad status which was not requested
            for pod in pods:
                if pod + "-" in stdout_line:
                    stdout_line_allowed = True

            if stdout_line_allowed:
                if is_critical_state_in_stdout(cluster, stdout_line):
                    cluster.log.verbose("Failed pod detected: %s\n" % stdout_line)

                    if not failure_found:
                        failure_found = True
                        failures += 1

                    # just in case, skip the error a couple of times, what if it comes out of the failure state?
                    if failures > cluster.globals['pods']['allowed_failures']:
                        raise Exception('Pod entered a state of error, further proceeding is impossible')
                else:
                # we have to take into account any pod in not a critical state
                    running_pods_stdout += stdout_line + '\n'

        pods_ready = False
        if running_pods_stdout and running_pods_stdout != "" and "0/1" not in running_pods_stdout:
            pods_ready = True
            for pod in pods:
                # it is necessary to look for pods with the name "xxxx-xxxx-" instead of "xxxx-xxxx" because
                # "xxxx-xxxx" may be the name of the namespace in which another healthy pod will be running
                if pod + "-" not in running_pods_stdout:
                    pods_ready = False

        if pods_ready:
            cluster.log.debug("Pods are ready!")
            cluster.log.debug(running_pods_stdout)
            return
        else:
            retries -= 1
            cluster.log.debug("Pods are not ready yet... (%ss left)" % (retries * timeout))
            cluster.log.debug(running_pods_stdout)
            time.sleep(timeout)

    raise Exception('In the expected time, the pods did not become ready')


def is_critical_state_in_stdout(cluster, stdout):
    for state in cluster.globals['pods']['critical_states']:
        if state in stdout:
            return True
    return False


# **** TEMPLATES ****

def convert_template(cluster, config):
    return _convert_file(config)


def verify_template(cluster, config):
    return _verify_file(config, "Template")


def apply_template(cluster, config, plugin_name=None):
    return _apply_file(cluster, config, "Template")


# **** EXPECT ****

def convert_expect(cluster, config):
    if config.get('daemonsets') is not None and isinstance(config['daemonsets'], list):
        config['daemonsets'] = {
            'list': config['daemonsets']
        }
    if config.get('replicasets') is not None and isinstance(config['replicasets'], list):
        config['replicasets'] = {
            'list': config['replicasets']
        }
    if config.get('statefulsets') is not None and isinstance(config['statefulsets'], list):
        config['statefulsets'] = {
            'list': config['statefulsets']
        }
    if config.get('deployments') is not None and isinstance(config['pods'], list):
        config['deployments'] = {
            'list': config['deployments']
        }
    if config.get('pods') is not None and isinstance(config['pods'], list):
        config['pods'] = {
            'list': config['pods']
        }
    return config


def apply_expect(cluster, config, plugin_name=None):
    # TODO: Add support for expect services and expect nodes

    plugins_timeout = cluster.globals['pods']['expect']['plugins']['timeout']
    plugins_retries = cluster.globals['pods']['expect']['plugins']['retries']

    for expect_type, expect_conf in config.items():
        if expect_type == 'daemonsets':
            expect_daemonset(cluster, config['daemonsets']['list'],
                             timeout=config['daemonsets'].get('timeout', plugins_timeout),
                             retries=config['daemonsets'].get('retries', plugins_retries))

        elif expect_type == 'replicasets':
            expect_replicaset(cluster, config['replicasets']['list'],
                              timeout=config['replicasets'].get('timeout', plugins_timeout),
                              retries=config['replicasets'].get('retries', plugins_retries))

        elif expect_type == 'statefulsets':
            expect_statefulset(cluster, config['statefulsets']['list'],
                               timeout=config['statefulsets'].get('timeout', plugins_timeout),
                               retries=config['statefulsets'].get('retries', plugins_retries))

        elif expect_type == 'deployments':
            expect_deployment(cluster, config['deployments']['list'],
                              timeout=config['deployments'].get('timeout', plugins_timeout),
                              retries=config['deployments'].get('retries', plugins_retries))

        elif expect_type == 'pods':
            expect_pods(cluster, config['pods']['list'],
                        namespace=config['pods'].get('namespace'),
                        timeout=config['pods'].get('timeout', plugins_timeout),
                        retries=config['pods'].get('retries', plugins_retries))


# **** PYTHON ****

def verify_python(cluster, step):
    # TODO: verify fields types and contents
    return


def apply_python(cluster, step, plugin_name=None):
    module_path, _ = utils.determine_resource_absolute_file(step['module'])
    method_name = step['method']
    method_arguments = step.get('arguments', {})

    cluster.log.debug("Running method %s from %s module..." % (method_name, module_path))
    module_filename = os.path.basename(module_path)
    spec = importlib.util.spec_from_file_location(os.path.splitext(module_filename)[0], module_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    getattr(module, method_name)(cluster, **method_arguments)


# **** THIRDPARTIES ****

def verify_thirdparty(cluster, thirdparty):
    defined_thirdparties = list(cluster.inventory['services'].get('thirdparties', {}).keys())
    if thirdparty not in defined_thirdparties:
        raise Exception('Specified thirdparty %s not found in thirdpartirs definition. Expected any of %s.'
                        % (thirdparty, defined_thirdparties))


def apply_thirdparty(cluster: KubernetesCluster, thirdparty: str, plugin_name=None):
    return thirdparties.install_thirdparty(cluster.nodes['all'], thirdparty)


# **** SHELL ****

def convert_shell(cluster, config):
    if isinstance(config, str):
        config = {
            'command': config
        }
    return config


def verify_shell(cluster, config):
    out_vars = config.get('out_vars', [])
    groups = config.get('groups', [])
    nodes = config.get('nodes', [])
    explicit_group = cluster.create_group_from_groups_nodes_names(groups, nodes)
    if out_vars and (groups or nodes) and explicit_group.nodes_amount() != 1:
        raise Exception('Shell output variables could be used for single-node groups, but multi-node group was found')

    in_vars = config.get('in_vars', [])
    words_splitter = re.compile('\W')
    for var in chain(in_vars, out_vars):
        var_name = var['name']
        if len(words_splitter.split(var_name)) > 1:
            raise Exception(f"'{var_name}' is not a valid shell variable name")

    # TODO: verify fields types and contents


def apply_shell(cluster, step, plugin_name=None):
    commands = step['command']
    sudo = step.get('sudo', False)
    groups = step.get('groups', [])
    nodes = step.get('nodes', [])
    in_vars = step.get('in_vars', [])
    out_vars = step.get('out_vars', [])
    vars_separator = "~~~~EXPORTED_VARIABLE~~~~"

    if not groups and not nodes:
        common_group = cluster.nodes['control-plane'].get_any_member()
    else:
        common_group = cluster.create_group_from_groups_nodes_names(groups, nodes)

    if isinstance(commands, list):
        commands = ' && '.join(commands)

    out_vars_aliases = {}
    for var in out_vars:
        var_name = var['name']
        if var_name in out_vars_aliases:
            # var is already exported, need to only add alternative alias
            out_vars_aliases[var_name].add(var.get('save_as', var_name))
            continue

        out_vars_aliases[var_name] = {var.get('save_as', var_name)}
        # print variable info to stdout in yaml format, separating data using `vars_separator`
        # quotes usage is important for following code to work correctly in different cases
        echo_var_cmd = f"echo {vars_separator} && " \
            f"echo name: {var_name} && " \
            f"echo 'value: |2-' && " \
            f"echo \"${var_name}\" | sed 's/^/  /'"
        commands = f"{commands} && {echo_var_cmd}"

    in_vars_dict = {}
    for var in in_vars:
        var_name = var['name']
        # get defined value or saved value, defaulting to empty value
        var_value = var.get('value', cluster.context['runtime_vars'].get(var_name, ''))
        # replace single-quotes with '"'"' to isolate all single quotes during ssh env inlining
        var_value = var_value.replace("'", "'\"'\"'")
        # wrap variable value with single-quotes for `inline_ssh_env` feature to work correctly with different content
        in_vars_dict[var_name] = f"'{var_value}'"

    method = common_group.run
    if sudo:
        method = common_group.sudo

    cluster.log.debug('Running shell command...')
    result = method(commands, env=in_vars_dict)

    if out_vars:
        stdout = list(result.values())[0].stdout
        stdout_parts = stdout.split(vars_separator)
        cluster.log.debug(stdout_parts[0])  # printing original user output
        for part in stdout_parts[1:]:
            var = yaml.safe_load(part)
            aliases = out_vars_aliases[var['name']]
            for alias in aliases:
                cluster.context['runtime_vars'][alias] = var['value']
    else:
        cluster.log.debug(result)

    return result


# **** ANSIBLE ****

def convert_ansible(cluster, config):
    if isinstance(config, str):
        config = {
            'playbook': config
        }
    return config


def _get_absolute_playbook(config) -> str:
    return utils.determine_resource_absolute_file(config['playbook'])[0]


def verify_ansible(cluster: KubernetesCluster, config):
    _get_absolute_playbook(config)
    if cluster.is_deploying_from_windows():
        raise Exception("Executing of playbooks on Windows deployer is currently not supported")
    # TODO: verify fields types and contents


def apply_ansible(cluster, step, plugin_name=None):
    playbook_path = _get_absolute_playbook(step)
    external_vars = step.get('vars', {})
    become = step.get('become', False)
    groups = step.get('groups', [])
    nodes = step.get('nodes', [])

    command = 'ansible-playbook -i ansible-inventory.ini %s' % playbook_path

    if become:
        command += ' -b'

    if groups or nodes:
        common_group = cluster.create_group_from_groups_nodes_names(groups, nodes)
        command += ' --limit %s' % ','.join(common_group.get_nodes_names())

    if external_vars:
        _vars = []
        for k, v in external_vars.items():
            _vars.append('%s=%s' % (k, v))
        command += ' --extra-vars "%s"' % ' '.join(_vars)

    cluster.log.verbose("Running shell \"%s\"" % command)

    result = subprocess.run(command, stdout=sys.stdout, stderr=sys.stderr, shell=True)
    if result.returncode != 0:
        raise Exception("Failed to apply ansible plugin, see error above")

    return result


def apply_helm(cluster: KubernetesCluster, config, plugin_name=None):
    chart_path = get_local_chart_path(cluster.log, config)
    process_chart_values(config, chart_path)

    from kubemarine import kubernetes
    local_config_path = kubernetes.fetch_admin_config(cluster)

    with utils.open_external(os.path.join(chart_path, 'Chart.yaml'), 'r') as stream:
        chart_metadata = yaml.safe_load(stream)
        chart_name = chart_metadata["name"]

    cluster.log.debug("Running helm chart %s" % chart_name)

    release = config.get('release', chart_name)
    cluster.log.debug("Deploying release %s" % release)

    namespace = config.get('namespace')
    if not namespace:
        cluster.log.verbose('Namespace configuration is missing, "default" namespace will be used')
        namespace = "default"

    prepare_for_helm_command = f'helm --kubeconfig {local_config_path} -n {namespace} '

    cluster.log.verbose("Check if chart already has been installed")
    # todo probably use single command helm upgrade --install
    command = prepare_for_helm_command + 'list -q'
    helm_existed_releases = subprocess.check_output(command, shell=True).decode('utf-8')

    if release in helm_existed_releases.splitlines():
        cluster.log.debug("Deployed release %s is found. Upgrading it..." % release)
        deployment_mode = "upgrade"
    else:
        cluster.log.debug("Deployed release %s is not found. Installing it..." % release)
        deployment_mode = "install"

    command = prepare_for_helm_command + f'{deployment_mode} {release} {chart_path} --debug'
    output = subprocess.check_output(command, shell=True)
    cluster.log.debug(output.decode('utf-8'))

    return output


def process_chart_values(config, local_chart_path):
    config_values = config.get("values")
    config_values_file = config.get("values_file")

    if config_values is not None:
        with utils.open_external(os.path.join(local_chart_path, 'values.yaml'), 'r+') as stream:
            original_values = yaml.safe_load(stream)
            stream.seek(0)
            merged_values = default_merger.merge(original_values, config_values)
            stream.write(yaml.dump(merged_values))
            stream.truncate()
    else:
        if config_values_file is not None:
            with utils.open_external(os.path.join(local_chart_path, 'values.yaml'), 'r+') as stream:
                with utils.open_external(config_values_file, 'r+') as additional_stream:
                    original_values = yaml.safe_load(stream)
                    additional_values = yaml.safe_load(additional_stream)
                    if additional_values is None:
                        return
                    stream.seek(0)
                    merged_values = default_merger.merge(original_values, additional_values)
                    stream.write(yaml.dump(merged_values))
                    stream.truncate()


def get_local_chart_path(log, config):
    chart_path = config.get('chart_path')

    is_curl = chart_path[:4] == 'http' and '://' in chart_path[4:8]

    local_chart_folder = "local_chart_folder"
    if os.path.isdir(local_chart_folder):
        remove_tree(local_chart_folder)
    mkpath(local_chart_folder)
    if is_curl:
        log.verbose('Chart download via curl detected')
        destination = os.path.basename(chart_path)

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        # todo probably add option which will manage if certificate should be verified?
        ctx.verify_mode = ssl.CERT_NONE
        with urllib.request.urlopen(chart_path, context=ctx) as u, \
                open(destination, 'wb') as f:
            shutil.copyfileobj(u, f)

        extension = destination.split('.')[-1]
        if extension == 'zip':
            log.verbose('Unzip will be used for unpacking')
            with zipfile.ZipFile(destination, 'r') as zf:
                zf.extractall(local_chart_folder)
        else:
            log.verbose('Tar will be used for unpacking')
            with tarfile.open(destination, "r:gz") as tf:
                tf.extractall(local_chart_folder)
    else:
        log.debug("Create copy of chart to work with")
        copy_tree(chart_path, local_chart_folder)

    # Find all Chart.yaml files in the chart.
    glob_search = os.path.join(local_chart_folder, '**', 'Chart.yaml')
    chart_metadata = glob.glob(glob_search, recursive=True)
    if not chart_metadata:
        raise Exception("Incorrect format of helm chart: Chart.yaml not found")

    # Sort by number of parts in path to find outermost Chart.yaml
    chart_metadata.sort(key=lambda path: len(path.split(os.sep)))
    local_chart_folder = os.path.dirname(chart_metadata[0])
    log.debug("Detected chart path = %s" % local_chart_folder)

    # Check all nested Chart.yaml are inside chart path
    for i in range(1, len(chart_metadata)):
        if not os.path.commonpath([chart_metadata[i], local_chart_folder]) == local_chart_folder:
            raise Exception(
                f"Incorrect format of helm chart: inner {chart_metadata[i]} is not inside {local_chart_folder} directory.")

    return local_chart_folder


def convert_config(cluster, config):
    return _convert_file(config)


def verify_config(cluster, config):
    return _verify_file(config, "Config")


def apply_config(cluster, config, plugin_name=None):
    return _apply_file(cluster, config, "Config")


def _convert_file(config):
    if isinstance(config, str):
        config = {
            'source': config
        }
    return config


def get_source_absolute_pattern(config) -> Tuple[str, bool]:
    abs_dir, is_external = utils.determine_resource_absolute_dir(config['source'])
    basename = os.path.basename(config['source'])
    return os.path.join(abs_dir, basename), is_external


def _verify_file(config, file_type):
    """
        Verifies if the path matching the config 'source' key exists and points to
        existing files.
    """

    # Determite absolute path to templates
    source, _ = get_source_absolute_pattern(config)
    files = glob.glob(source)

    if len(files) == 0:
        raise Exception('Cannot find any %s files matching this '
                        'source value: %s' % (file_type, source))

    for file in files:
        if not os.path.isfile(file):
            raise Exception('%s resource %s is not a file' % (file_type, file))
        # TODO: verify fields types and contents


def _apply_file(cluster: KubernetesCluster, config: dict, file_type: str) -> None:
    """
        Apply yamls as is or
        renders and applies templates that match the config 'source' key.
    """
    log = cluster.log
    do_render = config.get('do_render', True)

    source, is_external = get_source_absolute_pattern(config)
    files = glob.glob(source)

    for file in files:
        cfg_copy = dict(config)
        source_filename = os.path.basename(file)
        source = file
        if do_render:
            # templates usually have '.j2' extension, which we want to remove from resulting filename
            # but we also support usual '.yaml' files without '.j2' extension, in this case we do not want to remove extension
            split_extension = os.path.splitext(source_filename)
            if split_extension[1] == ".j2":
                source_filename = split_extension[0]

            render_vars = {**cluster.inventory, 'runtime_vars': cluster.context['runtime_vars']}
            with utils.open_utf8(file, 'r') as template_stream:
                generated_data = jinja.new(log).from_string(template_stream.read()).render(**render_vars)

            utils.dump_file(cluster, generated_data, source_filename)
            source = io.StringIO(generated_data)
        elif not is_external:
            with utils.open_utf8(file, 'r') as config_stream:
                source = io.StringIO(config_stream.read())

        cfg_copy['source'] = source

        destination_path = cfg_copy.setdefault('destination', '/etc/kubernetes/%s' % source_filename)

        log.debug("Uploading %s..." % file_type)
        log.debug("\tSource: %s" % file)
        log.debug("\tDestination: %s" % destination_path)

        apply_source(cluster, cfg_copy)


def apply_source(cluster: KubernetesCluster, config: dict) -> None:
    """
        Apply resource from 'source' key as is.
    """
    # Set needed settings from config
    apply_required = config.get('apply_required', True)
    use_sudo = config.get('sudo', True)
    destination_groups = config.get('destination_groups', [])
    destination_nodes = config.get('destination_nodes', [])
    apply_groups = config.get('apply_groups', [])
    apply_nodes = config.get('apply_nodes', [])
    source = config['source']
    destination_path = config['destination']
    apply_command = config.get('apply_command', 'kubectl apply -f %s' % destination_path)

    if not destination_groups and not destination_nodes:
        destination_common_group = cluster.nodes['control-plane']
    else:
        destination_common_group = cluster.create_group_from_groups_nodes_names(destination_groups, destination_nodes)

    if not apply_groups and not apply_nodes:
        apply_common_group = cluster.nodes['control-plane'].get_any_member()
    else:
        apply_common_group = cluster.create_group_from_groups_nodes_names(apply_groups, apply_nodes)

    destination_common_group.put(source, destination_path, backup=True, sudo=use_sudo)

    if apply_required:
        method = apply_common_group.run
        if use_sudo:
            method = apply_common_group.sudo
        cluster.log.debug("Applying yaml...")
        method(apply_command, hide=False)
    else:
        cluster.log.debug('Apply is not required')


procedure_types = {
    'template': {
        'convert': convert_template,
        'verify': verify_template,
        'apply': apply_template
    },
    'expect': {
        'convert': convert_expect,
        'apply': apply_expect
    },
    'python': {
        'verify': verify_python,
        'apply': apply_python
    },
    'thirdparty': {
        'verify': verify_thirdparty,
        'apply': apply_thirdparty
    },
    'shell': {
        'convert': convert_shell,
        'verify': verify_shell,
        'apply': apply_shell
    },
    'ansible': {
        'convert': convert_ansible,
        'verify': verify_ansible,
        'apply': apply_ansible
    },
    'helm': {
        'apply': apply_helm
    },
    'config': {
        'convert': convert_config,
        'verify': verify_config,
        'apply': apply_config
    },
}
