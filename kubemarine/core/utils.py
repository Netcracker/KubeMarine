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
import difflib
import hashlib
import io
import ipaddress
import json
import os
import re
import shutil
import sys
import time
import tarfile
import uuid
from collections import OrderedDict
from copy import deepcopy
from datetime import datetime

from typing import Tuple, Callable, List, TextIO, cast, Union, Dict, Sequence, Optional, NoReturn, BinaryIO

import deepdiff  # type: ignore[import-untyped]
import yaml
import ruamel.yaml

from pathvalidate import sanitize_filepath
from ruamel.yaml import CommentedMap
from useful_types import SupportsAllComparisons

from kubemarine.core import log
from kubemarine.core.errors import pretty_print_error


def do_fail(message: str = '', reason: BaseException = None, hint: str = '', logger: log.EnhancedLogger = None) -> NoReturn:

    if not logger:
        sys.stderr.write("\033[91m")

    pretty_print_error(message, reason, logger)

    # Please do not rewrite this to logging approach:
    # hint should be visible only in stdout and without special formatting
    if hint != "":
        sys.stderr.write("\n")
        sys.stderr.write(hint + "\n")

    if not logger:
        sys.stderr.write("\033[0m")

    sys.exit(1)


def get_elapsed_string(start: float, end: float) -> str:
    elapsed = end - start
    hours, remainder = divmod(elapsed, 3600)
    minutes, seconds = divmod(remainder, 60)
    return '{:02}h {:02}m {:02}s'.format(int(hours), int(minutes), int(seconds))


def prepare_dump_directory(context: dict) -> None:
    args: dict = context['execution_arguments']
    location = args['dump_location']
    reset_directory = not args['disable_dump_cleanup']
    dumpdir = os.path.join(location, 'dump')
    if reset_directory and os.path.exists(dumpdir) and os.path.isdir(dumpdir):
        shutil.rmtree(dumpdir)

    if not args['disable_dump']:
        os.makedirs(dumpdir, exist_ok=True)


def make_ansible_inventory(location: str, c: object) -> None:
    from kubemarine.core.cluster import KubernetesCluster  # pylint: disable=cyclic-import
    cluster = cast(KubernetesCluster, c)

    inventory = cluster.inventory
    roles = []
    for node in inventory['nodes']:
        for role in node['roles']:
            if role not in roles:
                roles.append(role)

    config: dict = {
        'all': [
            'localhost ansible_connection=local'
        ],
        'cluster:children': []
    }

    already_global_defined = []

    for role in roles:
        config[role] = []
        config['cluster:children'].append(role)
        for node in cluster.nodes[role].get_ordered_members_configs_list():
            record = "%s ansible_host=%s ansible_ssh_user=%s ansible_ssh_pass=%s ansible_ssh_private_key_file=%s ip=%s" % \
                     (node['name'],
                      node['connect_to'],
                      node.get('username', cluster.globals['connection']['defaults']['username']),
                      node.get('password'),
                      node.get('keyfile'),
                      node['internal_address'])
            if node.get('address') is not None:
                record += ' external_ip=%s' % node['address']

            if node['name'] not in already_global_defined:
                config['all'].append(record)
                # to avoid duplicate definition in global section we have to check is that was already defined?
                already_global_defined.append(node['name'])

            config[role].append(node['name'])

    config['cluster:vars'] = [
        'ansible_become=True'
    ]

    for group in ['services', 'plugins']:
        for service_name, service_configs in inventory.get(group, {}).items():
            # write to inventory only plugins, which will be installed
            if group == 'plugins' and not service_configs.get('install', False):
                continue

            config['cluster:vars'].append('\n# %s.%s' % (group, service_name))

            if isinstance(service_configs, dict):

                for config_name, config_value in service_configs.items():
                    if config_name in ('installation', 'install'):
                        continue

                    if isinstance(config_value, (dict, list)):
                        config_value = json.dumps(config_value)
                    config['cluster:vars'].append('%s_%s=%s' % (
                        # TODO: Rewrite replace using regex
                        service_name.replace('-', '_').replace('.', '_').replace('/', '_'),
                        config_name.replace('-', '_').replace('.', '_').replace('/', '_'),
                        config_value))
            else:
                config_value = json.dumps(service_configs)
                config['cluster:vars'].append('%s=%s' % (
                    service_name.replace('-', '_').replace('.', '_'),
                    config_value))

    config_compiled = ''
    for section_name, strings in config.items():
        config_compiled += '[%s]' % section_name
        for string in strings:
            config_compiled += '\n' + string
        config_compiled += '\n\n'

    dump_file({}, config_compiled, location, dump_location=False)


def get_current_timestamp_formatted() -> str:
    return datetime.now().strftime("%Y-%m-%d-%H-%M-%S")


def merge_vrrp_ips(procedure_inventory: dict, inventory: dict) -> None:
    # This method is currently unused.
    # If it is ever supported when adding and removing node,
    # it will be necessary to more accurately install and reconfigure the keepalived on existing nodes.
    # Also, it is desirable to change the section format, for example, as for etc_hosts.

    if "vrrp_ips" in inventory and len(inventory["vrrp_ips"]) > 0:
        raise Exception("vrrp_ips section already defined, merging not supported yet")
    else:
        inventory["vrrp_ips"] = procedure_inventory["vrrp_ips"]

    if isinstance(inventory, OrderedDict):
        inventory.move_to_end("vrrp_ips", last=False)


def is_dump_allowed(context: dict, filename: str) -> bool:
    args = context['execution_arguments']
    if args['disable_dump'] \
            and not (filename in ClusterStorage.PRESERVED_DUMP_FILES
                     and context['preserve_inventory']
                     and not args.get('without_act', False)):
        return False

    return True


def dump_file(context: Union[dict, object], data: Union[TextIO, str], filename: str,
              *, dump_location: bool = True) -> None:
    if dump_location:
        if not isinstance(context, dict):
            # cluster is passed instead of the context directly
            from kubemarine.core.cluster import KubernetesCluster  # pylint: disable=cyclic-import
            cluster = cast(KubernetesCluster, context)
            context = cluster.context

        if not is_dump_allowed(context, filename):
            return

        target_path = get_dump_filepath(context, filename)
    else:
        target_path = get_external_resource_path(filename)
    # sanitize_filepath is needed for windows/macOS, where some symbols are restricted in file path,
    # but they can appear in target path. They will be replaced with '_'
    target_path = sanitize_filepath(target_path, replacement_text='_')

    os.makedirs(os.path.dirname(target_path), exist_ok=True)

    if isinstance(data, io.StringIO):
        text = data.getvalue()
    elif isinstance(data, str):
        text = data
    else:
        text = data.read()

    with open_utf8(target_path, 'w') as file:
        file.write(text)


def get_dump_directory(context: dict) -> str:
    parts = [context['execution_arguments']['dump_location'], 'dump']
    if 'dump_subdir' in context:
        parts.append(context['dump_subdir'])

    dump_directory: str = os.path.join(*parts)
    return dump_directory


def get_dump_filepath(context: dict, filename: str) -> str:
    return get_external_resource_path(os.path.join(get_dump_directory(context), filename))


def wait_command_successful(logger: log.EnhancedLogger, attempt: Callable[[], bool],
                            retries: int, timeout: int) -> None:
    while retries > 0:
        logger.debug("Waiting for command to succeed, %s retries left" % retries)
        result = attempt()
        if result:
            logger.debug("Command succeeded")
            return
        retries = retries - 1
        time.sleep(timeout)
    raise Exception("Command failed")


def open_utf8(path: str, mode: str = 'r') -> TextIO:
    return cast(TextIO, open(path, mode + 't', encoding='utf-8'))


def open_internal(path: str, mode: str = 'r') -> TextIO:
    return open_utf8(get_internal_resource_path(path), mode)


def open_external(path: str, mode: str = 'r') -> TextIO:
    return open_utf8(get_external_resource_path(path), mode)


def read_internal(path: str) -> str:
    with open_internal(path) as f:
        return f.read()


def read_external(path: str) -> str:
    with open_external(path) as f:
        return f.read()


def get_external_resource_path(path: str) -> str:
    return os.path.abspath(path)


def get_internal_resource_path(path: str) -> str:
    return os.path.abspath(
        os.path.join(os.path.dirname(__file__), '..', path)
    )


def determine_resource_absolute_file(path: str) -> Tuple[str, bool]:
    """
    Get and verify absolute path to resource file
    :param path: Relative path to resource
    :return: Tuple of absolute path to resource file and flag defining if is an external resource
    """
    # is resource exists as it is defined?
    initial_definition = get_external_resource_path(path)
    if os.path.isfile(initial_definition):
        return initial_definition, True

    # is resource exists as internal resource?
    patched_definition = get_internal_resource_path(path)
    if os.path.isfile(patched_definition):
        return patched_definition, False

    raise Exception('Requested resource %s is not exists at %s or %s' % (path, initial_definition, patched_definition))


def determine_resource_absolute_dir(path: str) -> Tuple[str, bool]:
    """
    Get and verify absolute path to resource directory
    :param path: Relative path to resource
    :return: Tuple of absolute path to resource directory and flag defining if is an external resource
    """
    dirname = os.path.dirname(path)
    # is resource dir exists as it is defined?
    initial_definition = get_external_resource_path(dirname)
    if os.path.isdir(initial_definition):
        return initial_definition, True

    # is resource dir exists as internal resource?
    patched_definition = get_internal_resource_path(dirname)
    if os.path.isdir(patched_definition):
        return patched_definition, False

    raise Exception(
        'Requested resource directory %s is not exists at %s or %s' % (path, initial_definition, patched_definition))


def get_local_file_sha1(filename: str) -> str:
    with open(filename, 'rb') as f:
        return get_stream_sha1(f)


def get_stream_sha1(stream: BinaryIO) -> str:
    sha1 = hashlib.sha1()

    # Read by chunks of 2^16 bytes (65536) and calculate aggregated SHA1
    while True:
        data = stream.read(2 ** 16)
        if not data:
            break
        sha1.update(data)

    return sha1.hexdigest()


def get_remote_tmp_path(filename: str = None, ext: str = None) -> str:
    if filename is None:
        filename = uuid.uuid4().hex

    if ext is not None:
        filename += '.' + ext

    return "/tmp/" + filename


def yaml_structure_preserver() -> ruamel.yaml.YAML:
    """YAML loader and dumper which saves original structure"""
    ruamel_yaml = ruamel.yaml.YAML()
    ruamel_yaml.preserve_quotes = True
    return ruamel_yaml


def deepcopy_yaml(data: dict) -> dict:
    if isinstance(data, CommentedMap):
        ruamel_yaml = yaml_structure_preserver()
        # Dump and parse yaml object to work around ruamel.yaml bug
        # https://sourceforge.net/p/ruamel-yaml/tickets/410/
        buf = io.StringIO()
        ruamel_yaml.dump(data, buf)
        data = ruamel_yaml.load(buf.getvalue())
        return data

    return deepcopy(data)


def subdict_yaml(data: dict, keys: Sequence[str]) -> dict:
    items = (item for item in data.items() if item[0] in keys)
    if isinstance(data, CommentedMap):
        return CommentedMap(items)
    else:
        return dict(items)


def convert_native_yaml(data: dict) -> dict:
    if isinstance(data, CommentedMap):
        buf = io.StringIO()
        yaml_structure_preserver().dump(data, buf)
        data = yaml.safe_load(io.StringIO(buf.getvalue()))

    return data


def identity(x: str) -> str:
    return x


def is_sorted(l: Sequence[str], key: Callable[[str], SupportsAllComparisons] = None) -> bool:
    """
    Check that the specified list is sorted.

    :param l: list to check
    :param key: custom key function to customize the sort order
    :return: boolean flag if the list is sorted
    """
    if key is None:
        key = identity
    return all(key(l[i]) <= key(l[i + 1]) for i in range(len(l) - 1))


def map_sorted(map_: CommentedMap, key: Callable[[str], SupportsAllComparisons] = None) -> CommentedMap:
    """
    Check that the specified CommentedMap is sorted, or create new sorted map from it otherwise.

    :param map_: CommentedMap instance to check
    :param key: custom key function to customize the sort order of the map keys
    :return: the same or new sorted instance of the map
    """
    if key is not None:
        _key = key
    else:
        _key = identity
    map_keys: List[str] = list(map_)
    if not is_sorted(map_keys, key=_key):
        map_ = CommentedMap(sorted(map_.items(), key=lambda item: _key(item[0])))

    return map_


def insert_map_sorted(map_: CommentedMap, k: str, v: object, key: Callable[[str], SupportsAllComparisons] = None) -> None:
    """
    Insert new item to the CommentedMap or update the value for the existing key.
    The map should be already sorted.

    :param map_: sorted CommentedMap instance
    :param k: new key
    :param v: new value
    :param key: custom key function to customize the sort order of the map keys
    """
    if k in map_:
        map_[k] = v
        return

    if key is None:
        key = identity
    # Find position to insert new item maintaining the order
    pos = max((mi + 1 for mi, mv in enumerate(map_)
               if key(mv) < key(k)),
              default=0)

    map_.insert(pos, k, v)


def load_yaml(filepath: str) -> dict:
    try:
        with open_utf8(filepath, 'r') as stream:
            data: dict = yaml.safe_load(stream)
            return data
    except yaml.YAMLError as exc:
        do_fail(f"Failed to load {filepath}", exc)


def pretty_path(path: Sequence[Union[str, int]]) -> str:
    if not path:
        return ""
    return f"[{']['.join(map(repr, path))}]"


def strtobool(value: Union[str, bool]) -> bool:
    """
    The method check string and boolean value
    :param value: Value that should be checked
    """
    val = str(value).lower()
    if val in ('y', 'yes', 't', 'true', 'on', '1'):
        return True
    elif val in ('n', 'no', 'f', 'false', 'off', '0'):
        return False
    else:
        raise ValueError(f"invalid truth value {value!r}")


def strtoint(value: Union[str, int]) -> int:
    if isinstance(value, int):
        return value

    try:
        # whitespace required because python's int() ignores them
        return int(value.replace(' ', '.'))
    except ValueError:
        raise ValueError(f"invalid integer value {value!r}") from None


def print_diff(logger: log.EnhancedLogger, diff: deepdiff.DeepDiff) -> None:
    # Extra transformation to JSON is necessary,
    # because DeepDiff.to_dict() returns custom nested classes that cannot be serialized to yaml by default.
    logger.debug(yaml.safe_dump(yaml.safe_load(diff.to_json())))


def get_unified_diff(old: str, new: str, fromfile: str = '', tofile: str = '') -> Optional[str]:
    diff = list(difflib.unified_diff(
        old.splitlines(), new.splitlines(),
        fromfile=fromfile, tofile=tofile,
        lineterm=''))

    if diff:
        return '\n'.join(diff)

    return None


def get_yaml_diff(old: str, new: str, fromfile: str = '', tofile: str = '') -> Optional[str]:
    if yaml.safe_load(old) == yaml.safe_load(new):
        return None

    return get_unified_diff(old, new, fromfile, tofile)


def isipv(address: str, versions: List[int]) -> bool:
    return ipaddress.ip_network(address).version in versions


def get_version_filepath() -> str:
    return get_internal_resource_path("version")


def get_version() -> str:
    return read_internal(get_version_filepath()).strip()


def minor_version(version: str) -> str:
    """
    Converts vN.N.N to vN.N
    """
    return 'v' + '.'.join(map(str, _test_version(version, 3)[0:2]))


def major_version(version: str) -> str:
    """
    Converts vN.N.N to vN
    """
    return 'v' + '.'.join(map(str, _test_version(version, 3)[0:1]))


def version_key(version: str) -> Tuple[int, int, int]:
    """
    Converts vN.N.N to (N, N, N) that can be used in comparisons.
    """
    v = _test_version(version, 3)
    return v[0], v[1], v[2]


def minor_version_key(version: str) -> Tuple[int, int]:
    """
    Converts vN.N to (N, N) that can be used in comparisons.
    """
    v = _test_version(version, 2)
    return v[0], v[1]


def _test_version(version: str, numbers_amount: int) -> List[int]:
    # catch version without "v" at the first symbol
    is_rc = 0
    if version.startswith('v'):
        version_list: list = version[1:].split('.')
        # catch version with unexpected number or parts
        parts_num = len(version_list)
        try:
            for i, value in enumerate(version_list):
                # catch release candidate version like v1.29.0-rc.1
                if parts_num == 4 and i == 2 and value.endswith('-rc'):
                    value = value[:-3]
                    is_rc = 1
                # whitespace required because python's int() ignores them
                version_list[i] = int(value.replace(' ', '.'))
        except ValueError:
            pass
        else:
            if numbers_amount == parts_num - is_rc:
                return version_list[:numbers_amount]

    expected_pattern = 'v' + '.'.join('N+' for _ in range(numbers_amount))
    if numbers_amount == 3:
        expected_pattern += '[-rc.N+]'
    raise ValueError(f'Incorrect version \"{version}\" format, expected version pattern is \"{expected_pattern}\"')


def parse_aligned_table(table_text: str) -> List[Dict[str, str]]:
    """
    Parse aligned table into the list of {header: cell} map.
    The text with table can be initially produced, for example, by https://pkg.go.dev/text/tabwriter.

    :param table_text: aligned table as string
    :return: List of rows
    """
    rows = table_text.strip().split('\n')

    # Parse headers and their positions. No leading or trailing spaces are expected in the line.
    headers_line = rows[0]
    headers = []
    headers_pos = []
    pos = 0
    for match in re.finditer(r'\s+', headers_line):
        headers_pos.append(pos)
        span = match.span()
        headers.append(headers_line[pos:span[0]])
        pos = span[1]

    headers_pos.append(pos)
    headers.append(headers_line[pos:len(headers_line)])

    # Parse each row in the table,
    # provided that the columns start at the same positions as the headers
    headers_num = len(headers)
    data = []
    for row_text in rows[1:]:
        row = {}
        for i, header in enumerate(headers):
            if i == headers_num - 1:
                cell = row_text[headers_pos[i]:]
            else:
                cell = row_text[headers_pos[i]:headers_pos[i+1]]

            row[header] = cell.strip()

        data.append(row)

    return data


class ClusterStorage:
    """
    File preservation:
    1- Create folder where dumps are stored
    2- Rotating dumps in the storage folder
    3- Uploading dumps to nodes
    4- Copying dumps to new nodes
    """

    PRESERVED_DUMP_FILES = ['procedure.yaml', 'procedure_parameters',
                            'cluster.yaml', 'cluster_initial.yaml', 'cluster_finalized.yaml']

    def __init__(self, cluster: object, context: dict):
        from kubemarine.core.cluster import KubernetesCluster  # pylint: disable=cyclic-import
        self.cluster = cast(KubernetesCluster, cluster)
        self.context = context
        self.dir_path = "/etc/kubemarine/procedures/"
        self.dir_location = ''
        self.local_archive_path = ''

    def make_dir(self) -> None:
        """
        This method creates a directory in which logs about operations on the cluster will be stored.
        """
        readable_timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        initial_procedure = self.context["initial_procedure"]
        dir_name = readable_timestamp + "_" + initial_procedure + "/"
        self.dir_location = self.dir_path + dir_name
        self.cluster.nodes['control-plane'].sudo(f"mkdir -p {self.dir_location} ; sudo rm {self.dir_path + 'latest_dump'} ;"
                                                 f" sudo ln -s {self.dir_location} {self.dir_path + 'latest_dump'}")

    def upload_and_rotate(self) -> None:
        """
        This method uploads and unpacks the archive,
        then packs files with logs and maintains a structured storage of logs on the cluster.
        """
        control_planes = self.cluster.nodes["control-plane"]

        self.cluster.log.debug('Uploading archive with preserved information about the procedure.')
        remote_archive = self.dir_location + "local.tar.gz"
        control_planes.put(self.local_archive_path, remote_archive, sudo=True, compare_hashes=False)
        control_planes.sudo(
            f'tar -C {self.dir_location} -xzv --no-same-owner -f {remote_archive}  && '
            f'sudo rm -f {remote_archive} ')

        not_pack_file = self.cluster.inventory['procedure_history']['archive_threshold']
        delete_old = self.cluster.inventory['procedure_history']['delete_threshold']

        command = f'ls {self.dir_path} | grep -v latest_dump'
        node_group_results = control_planes.sudo(command)
        with control_planes.new_executor() as exe:
            for control_plane in exe.group.get_ordered_members_list():
                result = node_group_results[control_plane.get_host()]
                files = result.stdout.split()
                files.sort(reverse=True)
                for i, file in enumerate(files):
                    if not_pack_file <= i < delete_old:
                        if 'tar.gz' not in file:
                            control_plane.sudo(
                                f'tar -czvf {self.dir_path + file + ".tar.gz"} {self.dir_path + file} &&'
                                f'sudo rm -r {self.dir_path + file}')
                    elif i >= delete_old:
                        control_plane.sudo(f'rm -rf {self.dir_path + file}')

    def compress_archive(self, enriched: bool) -> None:
        """
        This method compose dump files in the local archive.
        """
        context = self.context
        self.local_archive_path = get_dump_filepath(context, "local.tar.gz")
        with tarfile.open(self.local_archive_path, "w:gz") as tar:
            dump_files = set(ClusterStorage.PRESERVED_DUMP_FILES)
            if not enriched:
                dump_files -= {'cluster.yaml', 'cluster_finalized.yaml'}

            for name in dump_files:
                source = get_dump_filepath(context, name)
                if os.path.exists(source):
                    tar.add(source, 'dump/' + name)
            tar.add(context['execution_arguments']['config'], 'cluster.yaml')
            tar.add(get_version_filepath(), 'version')

    def collect_procedure_info(self) -> None:
        """
        This method collects information about the type of procedure and the version of the tool we are working with.
        """
        context = self.context
        out = {}
        out['arguments'] = context['initial_cli_arguments']
        if 'proceeded_tasks' in context:
            out['finished_tasks'] = context['proceeded_tasks']
        out["initial_procedure"] = context["initial_procedure"]
        out["successfully_performed"] = context["successfully_performed"]
        out['status'] = context['status']
        output = yaml.dump(out)
        dump_file(context, output, "procedure_parameters")

    def upload_info_new_control_planes(self) -> None:
        """
        This method is used to transfer backup logs from the initial control-plane to the new control-planes.
        """
        new_control_planes = self.cluster.get_new_nodes().having_roles(['control-plane'])
        if new_control_planes.is_empty():
            return

        archive_name = 'dump_log_cluster.tar.gz'
        archive_dump_path = get_dump_filepath(self.context, archive_name)
        archive_remote_path = f"/tmp/{archive_name}"
        log = self.cluster.log

        control_plane = self.cluster.previous_nodes['control-plane'].get_first_member()
        data_copy_res = control_plane.sudo(f'tar -czvf {archive_remote_path} {self.dir_path}')
        log.verbose("Archive with procedures history is created:\n%s" % data_copy_res)
        control_plane.get(archive_remote_path, archive_dump_path)

        log.debug("Archive with procedures history is downloaded")

        for group in new_control_planes.get_ordered_members_list():
            group.put(archive_dump_path, archive_remote_path, sudo=True, compare_hashes=False)
            group.sudo(f'tar -C / -xzvf {archive_remote_path}')
            log.debug(f"Archive with procedures history is uploaded to {group.get_node_name()!r}")
