import io
import os
from datetime import datetime
from typing import List, Dict

import yaml

from kubemarine import plugins
from kubemarine.core.errors import KME
from kubemarine.core import utils

DELTAS_REMOTE_LOCATION = '/etc/kubemarine/deltas.txt'
DELTA_LOG_FORMAT = "%Y/%m/%d_%H:%M:%S"


class LocalDelta:
    def __init__(self, version, filepath, filename):
        file_extension = filename.split('.')[-1]
        filename_without_extension = ".".join(filename.split('.')[:-1])

        if file_extension == 'py':
            delta_type = 'python'
        elif file_extension in ['yaml', 'yml']:
            delta_type = 'yaml'
        else:
            delta_type = None

        self.version = version
        self.file = filepath
        self.name = filename_without_extension
        self.type = delta_type
        self.number = int(filename.split('_')[0])

    def is_valid(self):
        return self.type in ['python', 'yaml']

    def get_numeric_version(self) -> int or float:
        if self.version == 'unreleased':
            return float("inf")
        else:
            return utils.version_str_to_int(self.version)

    def apply(self, cluster, state: str):
        cluster.log.info(f'**** DELTA {self.name} APPLYING ****')

        cluster.log.verbose('Delta type: ' + self.type)
        cluster.log.verbose('Associated Kubemarine version: ' + self.version)

        if self.type == 'python':
            plugins.apply_python(cluster, {
                'module': self.file,
                'method': 'main'
            })
        elif self.type == 'yaml':
            with open(self.file, 'r') as s:
                yaml_delta = yaml.safe_load(s)
            actions = plugins.enrich_inventory_plugin_procedures(cluster,
                                                                 yaml_delta.get('actions', []))
            res = plugins.install_plugin(cluster, 'deltas', actions)
            if res == 'skipped':
                state = 'skipped'
        else:
            raise Exception(f'Failed to run unsupported '
                            f'delta type "{self.type}" at delta "{self.name}"')

        # update current applied deltas on remote env on every delta apply finish
        self.update_remote(cluster, state)

    def skip(self, cluster):
        self.update_remote(cluster, 'skipped')
        cluster.log.debug(f'**** DELTA {self.name} SKIPPED ****')

    def update_remote(self, cluster, state):
        if not isinstance(cluster.context.get('deltas'), dict):
            cluster.context['deltas'] = {}
        if not isinstance(cluster.context['deltas'].get('remote'), list):
            cluster.context['deltas']['remote'] = []
        cluster.context['deltas']['remote'].append(RemoteDelta(datetime.now(), self.name, state))
        update_remote_deltas(cluster)


class RemoteDelta:
    def __init__(self, date: datetime, name: str, state: str):
        self.date = date
        self.name = name
        self.state = state

        if isinstance(self.date, str):
            self.date = datetime.strptime(self.date, DELTA_LOG_FORMAT)

    def __str__(self):
        delta_date_str = self.date.strftime(DELTA_LOG_FORMAT)
        return f'{delta_date_str} {self.name} {self.state}'

    def get_local_delta(self, cluster=None):

        local_deltas = None

        # to speed up the process it is possible to pass cluster with context, but not mandatory
        if cluster is not None and cluster.context.get('deltas', {}).get('local') is not None:
            local_deltas = cluster.context['deltas']['local']

        if local_deltas is None:
            local_deltas = load_local_deltas_list()

        for local_delta in local_deltas:
            if local_delta.name == self.name:
                return local_delta

        return None


def load_local_deltas_list() -> List[LocalDelta]:
    local_deltas_list = []

    deltas_location = utils.get_resource_absolute_path('./deltas', script_relative=True)

    for filename in os.listdir(deltas_location):
        filepath = os.path.join(deltas_location, filename)
        if os.path.isfile(filepath):
            delta_obj = LocalDelta('unreleased', filepath, filename)
            if delta_obj.is_valid():
                local_deltas_list.append(delta_obj)
        else:
            for sub_filename in os.listdir(filepath):
                sub_filepath = os.path.join(filepath, sub_filename)
                if os.path.isfile(sub_filepath):
                    delta_obj = LocalDelta(filename, sub_filepath, sub_filename)
                    if delta_obj.is_valid():
                        local_deltas_list.append(delta_obj)

    return sorted(local_deltas_list, key=lambda d: d.get_numeric_version())


def load_remote_deltas_list(group) -> List[RemoteDelta] or None:
    remote_deltas = []
    # TODO: possibly replace with get?
    raw_results = group.sudo('cat ' + DELTAS_REMOTE_LOCATION, warn=True)

    # case, when deltas were never applied on this env and should not be validated
    if raw_results.is_all_failed():
        return None

    if raw_results.is_any_results_different():
        # TODO: print broken nodes, where deltas out of sync
        raise KME('KME0009')

    deltas_log_str = raw_results.get_simple_out(ignore_multiple_nodes=True).strip()
    for log_str in deltas_log_str.split('\n'):
        log_date, log_name, log_state = log_str.strip().replace('  ', ' ').split(' ')
        remote_deltas.append(RemoteDelta(log_date, log_name, log_state))

    return sorted(remote_deltas, key=lambda x: x.date)


def compare_deltas_lists(local_deltas, remote_deltas):
    is_different = False
    diff_list = []

    initial_remote_delta = remote_deltas[0]
    local_delta_i = -1
    for i, local_delta in enumerate(local_deltas):
        if local_delta.name == initial_remote_delta.name:
            local_delta_i = i
            break

    for i, local_delta in enumerate(local_deltas):

        # ignore old local deltas if remote contains only latest
        if local_delta_i != -1 and i < local_delta_i:
            continue

        local_delta_applied = False
        for remote_delta in remote_deltas:
            if local_delta.name == remote_delta.name:
                local_delta_applied = True
                break

        if not local_delta_applied:
            is_different = True
            diff_list.append(local_delta)

    return is_different, diff_list


def get_deltas_diff(cluster):
    # if deltas were already loaded into context
    if cluster.context.get('deltas') is not None:
        local_deltas = cluster.context['deltas']['local']
        remote_deltas = cluster.context['deltas']['remote']
    else:
        local_deltas = load_local_deltas_list()
        remote_deltas = load_remote_deltas_list(cluster.nodes['master'])

        cluster.context['deltas'] = {
            "local": local_deltas,
            "remote": remote_deltas
        }

    # case, when deltas were never applied on this env
    if remote_deltas is None:
        cluster.log.verbose('Deltas were not applied on this env yet,'
                            'validation is not applicable.')
        return False, None

    return compare_deltas_lists(local_deltas, remote_deltas)


def validate_remote_deltas(cluster):
    is_different, diff_list = get_deltas_diff(cluster)

    if is_different:
        reason_message = '- ' + ('\n - '.join(d.name for d in diff_list))
        raise KME('KME0010', reason=reason_message)


def update_remote_deltas(cluster):
    cluster.log.verbose('Updating remote deltas list...')
    deltas_str = ('\n'.join(map(str, cluster.context['deltas']['remote']))) + '\n'
    group = cluster.nodes['master']
    return group.put(io.StringIO(deltas_str), DELTAS_REMOTE_LOCATION, sudo=True, mkdir=True)


def apply_deltas(cluster, skip_deltas: List[str] = None, enforce_delta: str = None) -> List[str]:
    is_different, diff_list = get_deltas_diff(cluster)

    if skip_deltas is None:
        skip_deltas = []

    # case, when deltas were never applied on this env and should be initialized for the first time
    if diff_list is None:
        latest_local_delta = cluster.context['deltas']['local'][-1]
        latest_local_delta.update_remote(cluster, 'enforced')
        return [latest_local_delta]

    if is_different:
        enforce_delta_applied = False
        if enforce_delta is None:
            enforce_delta_applied = True
        for local_delta in diff_list:
            if (not enforce_delta_applied and local_delta.name != enforce_delta) \
                    or local_delta.name in skip_deltas:
                local_delta.skip(cluster)
                continue
            state = 'auto'
            if local_delta.name == enforce_delta:
                state = 'enforced'
                enforce_delta_applied = True
            local_delta.apply(cluster, state)
    else:
        cluster.log.info('All deltas up to date!')

    return diff_list


def get_remote_environment_kubemarine_version(cluster):
    remote_deltas = cluster.context.get('deltas', {}).get('remote')
    if not remote_deltas:
        return None

    remote_deltas = sorted(remote_deltas, key=lambda d: d.name)
    last_remote_delta = remote_deltas[-1]
    local_delta = last_remote_delta.get_local_delta(cluster)
    return local_delta.version
