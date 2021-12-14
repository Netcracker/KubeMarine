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

import glob
import importlib.util
import io
import os
import re
import subprocess
import sys
import time
from copy import deepcopy
from distutils.dir_util import copy_tree
from distutils.dir_util import remove_tree
from distutils.dir_util import mkpath
from itertools import chain

import yaml

from kubetool import jinja, thirdparties
from kubetool.core import utils
from kubetool.core.executor import RemoteExecutor
from kubetool.core.yaml_merger import default_merger
from kubetool.core.group import NodeGroup

# list of plugins owned and managed by kubetools
oob_plugins = [
    "calico",
    "flannel",
    "nginx-ingress-controller",
    "haproxy-ingress-controller",
    "kubernetes-dashboard",
    "local-path-provisioner",
]


def verify_inventory(inventory, cluster):
    supported_procedure_types = list(procedure_types.keys())

    for plugin_name, plugin_item in inventory["plugins"].items():
        for step in plugin_item.get('installation', {}).get('procedures', []):
            for procedure_type, configs in step.items():
                if procedure_type not in supported_procedure_types:
                    raise Exception('Unknown installation procedure type found in a plugin \'%s\'. '
                                    'Expected any of %s, but found \'%s\'.'
                                    % (plugin_name, supported_procedure_types, procedure_type))
                procedure_types[procedure_type]['verify'](cluster, configs)

    return inventory


def enrich_inventory(inventory, cluster):
    for plugin_name, plugin_item in inventory["plugins"].items():
        for i, step in enumerate(plugin_item.get('installation', {}).get('procedures', [])):
            for procedure_type, configs in step.items():
                if procedure_types[procedure_type].get('convert') is not None:
                    inventory["plugins"][plugin_name]['installation']['procedures'][i][procedure_type] = \
                        procedure_types[procedure_type]['convert'](cluster, configs)
    return inventory


def enrich_upgrade_inventory(inventory, cluster):
    if cluster.context.get("initial_procedure") != "upgrade":
        return inventory

    with open(utils.get_resource_absolute_path('resources/configurations/defaults.yaml', script_relative=True), 'r') \
            as stream:
        base_plugins = yaml.safe_load(stream)["plugins"]
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
    plugins_queue = []
    max_priority = 0
    for plugin_name, plugin_item in plugins.items():
        if plugin_item.get("install", False) and plugin_item.get("installation", {}).get('procedures') is not None:
            plugin_item['plugin_name'] = plugin_name
            plugins_queue.append(plugin_item)
            if plugin_item.get("installation", {}).get('priority') is not None \
                    and plugin_item['installation']['priority'] > max_priority:
                max_priority = plugin_item['installation']['priority']

    plugins_queue.sort(key=lambda item: item.get("installation", {}).get('priority', max_priority + 1))

    cluster.log.debug('The following plugins will be installed:')
    for plugin_item in plugins_queue:
        cluster.log.debug('%i. %s' % (
            plugin_item.get("installation", {}).get('priority', max_priority + 1),
            plugin_item['plugin_name']
        ))

    cluster.log.debug('Starting plugins installation:')

    for plugin_item in plugins_queue:
        install_plugin(cluster, plugin_item['plugin_name'], plugin_item["installation"]['procedures'])


def install_plugin(cluster, plugin_name, installation_procedure):
    cluster.log.debug("**** INSTALLING PLUGIN %s ****" % plugin_name)
    for step in installation_procedure:
        for apply_type, configs in step.items():
            procedure_types[apply_type]['apply'](cluster, configs)


def expect_pods(cluster, pods, timeout=None, retries=None, node=None, apply_filter=None):

    if isinstance(cluster, NodeGroup):
        # cluster is a group, not a cluster
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
        node = cluster.nodes['master'].get_first_member()

    command = 'kubectl get pods -A -o=wide'
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
                if 'Running' in stdout_line:
                    running_pods_stdout += stdout_line + '\n'
                elif is_critical_state_in_stdout(cluster, stdout_line):
                    cluster.log.verbose("Failed pod detected: %s\n" % stdout_line)

                    if not failure_found:
                        failure_found = True
                        failures += 1

                    # just in case, skip the error a couple of times, what if it comes out of the failure state?
                    if failures > cluster.globals['pods']['allowed_failures']:
                        raise Exception('Pod entered a state of error, further proceeding is impossible')

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
    _verify_file(config, "Template")


def apply_template(cluster, config):
    _apply_file(cluster, config, "Template")


# **** EXPECT ****

def convert_expect(cluster, config):
    if config.get('pods') is not None and isinstance(config['pods'], list):
        config['pods'] = {
            'list': config['pods']
        }
    return config


def verify_expect(cluster, config):
    if not config:
        raise Exception('Expect procedure is empty, but it should not be')
    if config.get('pods') is not None and config['pods'].get('list') is None:
        raise Exception('Pod expectation defined, but pods list is missing')


def apply_expect(cluster, config):
    # TODO: Add support for expect services and expect nodes
    if config.get('pods') is not None:
        expect_pods(cluster, config['pods']['list'],
                    timeout=config['pods'].get('timeout', cluster.globals['pods']['expect']['plugins']['timeout']),
                    retries=config['pods'].get('retries', cluster.globals['pods']['expect']['plugins']['retries']))


# **** PYTHON ****

def verify_python(cluster, step):
    if step.get('module') is None:
        raise Exception('Module path is missing for python in plugin steps, but should be defined. Step:\n%s' % step)
    if step.get('method') is None:
        raise Exception('Method name is missing for python in plugin steps, but should be defined. Step:\n%s' % step)
    # TODO: verify fields types and contents


def apply_python(cluster, step):
    module_path = utils.determine_resource_absolute_path(step['module'])
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


def apply_thirdparty(cluster, thirdparty):
    return thirdparties.install_thirdparty(cluster, thirdparty)

# **** SHELL ****

def convert_shell(cluster, config):
    if isinstance(config, str):
        config = {
            'command': config
        }
    return config


def verify_shell(cluster, config):
    if config.get('command') is None or config['command'] == '':
        raise Exception('Shell command is missing')

    out_vars = config.get('out_vars', [])
    explicit_group = cluster.create_group_from_groups_nodes_names(config.get('groups', []), config.get('nodes', []))
    if out_vars and explicit_group and explicit_group.nodes_amount() != 1:
        raise Exception('Shell output variables could be used for single-node groups, but multi-node group was found')

    in_vars = config.get('in_vars', [])
    words_splitter = re.compile('\W')
    for var in chain(in_vars, out_vars):
        if not var.get('name'):
            raise Exception('All output and input shell variables should have "name" property specified')
        var_name = var['name']
        if len(words_splitter.split(var_name)) > 1:
            raise Exception(f"'{var_name}' is not a valid shell variable name")

    # TODO: verify fields types and contents


def apply_shell(cluster, step):
    commands = step['command']
    sudo = step.get('sudo', False)
    groups = step.get('groups', [])
    nodes = step.get('nodes', [])
    in_vars = step.get('in_vars', [])
    out_vars = step.get('out_vars', [])
    vars_separator = "~~~~EXPORTED_VARIABLE~~~~"

    if not groups and not nodes:
        common_group = cluster.nodes['master'].get_any_member()
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


# **** ANSIBLE ****

def convert_ansible(cluster, config):
    if isinstance(config, str):
        config = {
            'playbook': config
        }
    # if config['playbook'][0] != '/':
    #     config['playbook'] = os.path.abspath(os.path.dirname(__file__) + '../../../' + config['playbook'])
    return config


def verify_ansible(cluster, config):
    if config.get('playbook') is None or config['playbook'] == '':
        raise Exception('Playbook path is missing')
    if not os.path.isfile(config['playbook']):
        raise Exception('Playbook file %s not exists' % config['location'])
    # TODO: verify fields types and contents


def apply_ansible(cluster, step):
    playbook_path = utils.determine_resource_absolute_path(step.get('playbook'))
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


def verify_helm(cluster, config):
    if config.get('chart_path') is None or config['chart_path'] == '':
        raise Exception('Chart path is missing')

    if cluster.inventory.get('public_cluster_ip') is None:
        raise Exception(f'public_cluster_ip is a mandatory parameter in the inventory in case of usage of helm plugin.')


def apply_helm(cluster, config):
    chart_path = get_local_chart_path(cluster.log, config)
    process_chart_values(config, chart_path)

    common_group = cluster.nodes['master'].get_first_member()

    cluster.log.debug('Loading kubeconfig from master...')
    kubeconfig = common_group.sudo("cat /root/.kube/config")

    kubeconfig_stdout = list(kubeconfig.values())[0].stdout

    # Replace cluster FQDN with ip
    public_cluster_ip = cluster.inventory.get('public_cluster_ip')
    cluster_name = cluster.inventory.get('cluster_name')
    kubeconfig_stdout = kubeconfig_stdout.replace(cluster_name, public_cluster_ip)

    cluster.log.debug("Writing config to file...")
    local_config_path = os.getcwd() + "/config"
    command = 'echo "%s" > %s' % (kubeconfig_stdout, local_config_path)
    subprocess.check_output(command, shell=True)

    with open(chart_path + '/Chart.yaml', 'r') as stream:
        chart_metadata = yaml.safe_load(stream)
        chart_name = chart_metadata["name"]

    cluster.log.debug("Running helm chart %s" % chart_name)

    namespace = config.get('namespace')
    if not namespace:
        cluster.log.verbose('Namespace configuration is missing, "default" namespace will be used')
        namespace = "default"

    prepare_for_helm_command = f'export KUBECONFIG="{local_config_path}"; cd "{chart_path}"; helm -n {namespace} '

    cluster.log.verbose("Check if chart already has been installed")
    command = prepare_for_helm_command + 'list -q'
    helm_existed_releases = subprocess.check_output(command, shell=True).decode('utf-8')

    command = f'echo "{helm_existed_releases}" | grep "^{chart_name}$" | cat'
    deployed_release = subprocess.check_output(command, shell=True)
    if deployed_release:
        cluster.log.debug("Deployed release %s is found. Upgrading it..." % chart_name)
        deployment_mode = "upgrade"
    else:
        cluster.log.debug("Deployed release %s is not found. Installing it..." % chart_name)
        deployment_mode = "install"

    command = prepare_for_helm_command + f'{deployment_mode} {chart_name} . --debug'
    output = subprocess.check_output(command, shell=True)
    cluster.log.debug(output.decode('utf-8'))


def process_chart_values(config, local_chart_path):
    config_values = config.get("values")
    config_values_file = config.get("values_file")

    if config_values is not None:
        with open(local_chart_path + '/values.yaml', 'r+') as stream:
            original_values = yaml.safe_load(stream)
            stream.seek(0)
            merged_values = default_merger.merge(original_values, config_values)
            stream.write(yaml.dump(merged_values))
            stream.truncate()
    else:
        if config_values_file is not None:
            with open(local_chart_path + '/values.yaml', 'r+') as stream:
                with open(config_values_file, 'r+') as additional_stream:
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

    local_chart_folder = os.getcwd() + "/local_chart_folder"
    if os.path.isdir(local_chart_folder):
        remove_tree(local_chart_folder)
    mkpath(local_chart_folder)
    if is_curl:
        log.verbose('Chart download via curl detected')
        destination = os.path.basename(chart_path)
        commands = 'curl -g -k %s -o %s' % (chart_path, destination)
        extension = destination.split('.')[-1]
        if extension == 'zip':
            log.verbose('Unzip will be used for unpacking')
            commands += ' && unzip %s -d %s' % (destination, local_chart_folder)
        else:
            log.verbose('Tar will be used for unpacking')
            commands += ' && tar -zxf %s -C %s' % (destination, local_chart_folder)
        log.debug(subprocess.check_output(commands, shell=True))
    else:
        log.debug("Create copy of chart to work with")
        copy_tree(chart_path, local_chart_folder)

    log.debug("Ready chart path = %s" % local_chart_folder)
    return local_chart_folder


def convert_config(cluster, config):
    return _convert_file(config)


def verify_config(cluster, config):
    _verify_file(config, "Config")


def apply_config(cluster, config):
    _apply_file(cluster, config, "Config")


def _convert_file(config):
    if isinstance(config, str):
        config = {
            'source': config
        }
    # if config['source'][0] != '/':
    #     config['source'] = os.path.abspath(os.path.dirname(__file__) + '../../../' + config['source'])
    return config


def _verify_file(config, file_type):
    """
        Verifies if the path matching the config 'source' key exists and points to
        existing files.
        """
    if config.get('source') is None or config['source'] == '':
        raise Exception('%s file source is missing' % file_type)

    # Determite absolute path to templates
    source = os.path.join(
        utils.determine_resource_absolute_dir(config['source']),
        os.path.basename(config['source'])
    )

    files = glob.glob(source)

    if len(files) == 0:
        raise Exception('Cannot find any %s files matching this '
                        'source value: %s' % (file_type, source))

    for file in files:
        source = utils.determine_resource_absolute_path(file)
        if not os.path.isfile(source):
            raise Exception('%s file %s not exists' % (file_type, source))
        # TODO: verify fields types and contents


def _apply_file(cluster, config, file_type):
    """
        Apply yamls as is or
        renders and applies templates that match the config 'source' key.
    """
    # Set needed settings from config
    apply_required = config.get('apply_required', True)
    use_sudo = config.get('sudo', True)
    destination_groups = config.get('destination_groups', [])
    destination_nodes = config.get('destination_nodes', [])
    apply_groups = config.get('apply_groups', [])
    apply_nodes = config.get('apply_nodes', [])
    do_render = config.get('do_render', True)

    # Determite absolute path to templates
    source = os.path.join(
        utils.determine_resource_absolute_dir(config['source']),
        os.path.basename(config['source'])
    )

    files = glob.glob(source)

    if len(files) == 0:
        raise Exception('Cannot find any %s files matching this '
                        'source value: %s' % (source, file_type))

    for file in files:
        source_filename = os.path.basename(file)

        if do_render:
            # templates usually have '.j2' extension, which we want to remove from resulting filename
            # but we also support usual '.yaml' files without '.j2' extension, in this case we do not want to remove extension
            split_extension = os.path.splitext(source_filename)
            if split_extension[1] == ".j2":
                source_filename = split_extension[0]

        destination_path = config.get('destination', '/etc/kubernetes/%s' % source_filename)
        apply_command = config.get('apply_command', 'kubectl apply -f %s' % destination_path)

        if not destination_groups and not destination_nodes:
            destination_common_group = cluster.nodes['master']
        else:
            destination_common_group = cluster.create_group_from_groups_nodes_names(destination_groups,
                                                                                    destination_nodes)

        if not apply_groups and not apply_nodes:
            apply_common_group = cluster.nodes['master'].get_any_member()
        else:
            apply_common_group = cluster.create_group_from_groups_nodes_names(apply_groups, apply_nodes)

        cluster.log.debug("Uploading %s..." % file_type)
        cluster.log.debug("\tSource: %s" % file)
        cluster.log.debug("\tDestination: %s" % destination_path)

        if do_render:
            render_vars = {**cluster.inventory, 'runtime_vars': cluster.context['runtime_vars']}
            generated_data = jinja.new(cluster.log).from_string(
                open(utils.determine_resource_absolute_path(file)).read()).render(**render_vars)
            utils.dump_file(cluster, generated_data, source_filename)
            destination_common_group.put(io.StringIO(generated_data), destination_path, backup=True, sudo=use_sudo)
        else:
            destination_common_group.put(utils.determine_resource_absolute_path(file), destination_path, backup=True, sudo=use_sudo)

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
        'verify': verify_expect,
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
        'verify': verify_helm,
        'apply': apply_helm
    },
    'config': {
        'convert': convert_config,
        'verify': verify_config,
        'apply': apply_config
    },
}
