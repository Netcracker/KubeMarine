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
import types
from collections import OrderedDict
from typing import Dict, List

import ruamel.yaml.resolver
import yaml

from kubemarine import procedures as proc

# Don't remove this line. The idna encoding
# is used by getaddrinfo when dealing with unicode hostnames,
# and in some cases, there appears to be a race condition
# where threads will get a LookupError on getaddrinfo() saying
# that the encoding doesn't exist.  Using the idna encoding before
# running any kubemarine code (and any threads it may create) ensures that
# the encodings.idna is imported and registered in the codecs registry,
# which will stop the LookupErrors from happening.
# See: https://bugs.python.org/issue29288
u''.encode('idna')

# Take pattern to resolve float used by ruamel instead of that is used by pyyaml.
# https://sourceforge.net/p/ruamel-yaml/code/ci/0.17.21/tree/resolver.py#l43
# Initially introduced for keepalived that generates random password string.
# The generated string might be also a valid exponential float, and should be dumped with quotes.
# See also:
# https://stackoverflow.com/questions/30458977/yaml-loads-5e-6-as-string-and-not-a-number
# https://github.com/yaml/pyyaml/issues/173
for ir in ruamel.yaml.resolver.implicit_resolvers:
    # YAML 1.1 and float implicit resolver
    if (1, 1) in ir[0] and 'tag:yaml.org,2002:float' in ir[1]:
        float_patched_resolver = (ir[1], ir[2], ir[3])
        # Globally change behaviour of yaml.safe_load and yaml.dump
        yaml.Dumper.add_implicit_resolver(*float_patched_resolver)  # type: ignore[no-untyped-call]
        yaml.SafeLoader.add_implicit_resolver(*float_patched_resolver)  # type: ignore[no-untyped-call]
        break


procedures = OrderedDict({
    'install': {
        'description': "Install a cluster from scratch",
        'group': 'installation'
    },
    'migrate_kubemarine': {
        'description': "Automatically perform migration to update the environment for the "
                       "current version of Kubemarine",
        'group': 'maintenance'
    },
    'upgrade': {
        'description': "Automatically upgrade the entire Kubernetes cluster to a new version",
        'group': 'maintenance'
    },
    'backup': {
        'description': "Backup Kubernetes resources and nodes content to backup file",
        'group': 'maintenance'
    },
    'restore': {
        'description': "Restore Kubernetes resources and nodes content from backup file",
        'group': 'maintenance'
    },
    'add_node': {
        'description': "Add new nodes to an existing cluster",
        'group': 'maintenance'
    },
    'remove_node': {
        'description': "Remove existing nodes from cluster",
        'group': 'maintenance'
    },
    'manage_psp': {
        'description': "Manage PSP on Kubernetes cluster",
        'group': 'maintenance'
    },
    'manage_pss': {
        'description': "Manage PSS on Kubernetes cluster",
        'group': 'maintenance'
    },
    'cert_renew': {
        'description': "Renew certificates on Kubernetes cluster",
        'group': 'maintenance'
    },
    'reboot': {
        'description': "Reboot Kubernetes nodes",
        'group': 'maintenance'
    },
    'check_iaas': {
        'description': "Check environment for compliance with IAAS requirements",
        'group': 'checks'
    },
    'check_paas': {
        'description': "Check environment for compliance with PAAS requirements",
        'group': 'checks'
    },
    'version': {
        'description': "Print current release version",
        'group': 'other'
    },
    'do': {
        'description': "Execute shell command on cluster nodes",
        'group': 'other'
    },
    'selftest': {
        'description': "Test internal imports and resources presence",
        'group': 'other'
    },
    'migrate_cri': {
        'description': "Migrate from Docker to Containerd",
        'group': 'maintenance'
    },
})


def main() -> None:
    arguments = sys.argv[1:]

    if len(arguments) > 0:
        if arguments[0] == 'selftest':
            return selftest()
        elif arguments[0] == 'version':
            return version()

    if len(arguments) < 1 or arguments[0] not in procedures.keys():
        descriptions_print_list = []
        max_module_name_size = len(max(procedures.keys(), key=len))

        items_description_by_groups: Dict[str, List[str]] = {}

        for module_name, module in procedures.items():
            items_description_by_groups.setdefault(module['group'], [])\
                .append('  %s%s  %s' % (module_name, ' ' * (max_module_name_size - len(module_name)), module['description']))

        previous_group = None
        for group, descriptions in items_description_by_groups.items():
            if group != previous_group:
                descriptions_print_list.append('\n%s:' % group.upper())
                previous_group = group
            for description in descriptions:
                descriptions_print_list.append(' ' + description)
        print('''The following procedures available:
%s

Usage: kubemarine <procedure> <arguments>
''' % '\n'.join(descriptions_print_list))
        sys.exit(1)

    result = proc.import_procedure(arguments[0]).main(arguments[1:])
    if result is not None:
        from kubemarine.testsuite import TestSuite
        if isinstance(result, TestSuite) and result.is_any_test_failed():
            sys.exit(1)


def version() -> None:
    from kubemarine.core import utils

    print('Kubemarine %s' % utils.get_version())


def selftest() -> None:
    print("Running selftest")

    time_start = int(round(time.time() * 1000))

    for procedure, procedure_details in procedures.items():
        print("\nImporting %s..." % procedure)

        if procedure in ['version', 'selftest']:
            continue

        module = proc.import_procedure(procedure)
        imports = []

        for attr in dir(module):
            if isinstance(getattr(module, attr), types.ModuleType):
                imports.append(attr)

        print("%s has %s imports" % (procedure, len(imports)))

        if "main" not in dir(module):
            raise Exception("No main method in %s" % procedure)
        if procedure not in ["do", "migrate_kubemarine"]:
            if "tasks" not in dir(module):
                raise Exception("Tasks tree is not presented in %s" % procedure)
            if not isinstance(module.tasks, OrderedDict):
                raise Exception("Tasks are not ordered in %s" % procedure)
            if not module.tasks:
                raise Exception("Tasks are empty in %s" % procedure)

        print("%s OK" % procedure)

        del module
        proc.deimport_procedure(procedure)

    print("\nTrying fake cluster...")

    from kubemarine import demo

    demo.new_cluster(demo.generate_inventory(**demo.FULLHA))

    print('\nValidating patch duplicates ...')

    module = proc.import_procedure('migrate_kubemarine')
    patches = module.load_patches()
    patch_ids = [patch.identifier for patch in patches]
    unique = set()
    for p_id in patch_ids:
        if p_id in unique:
            raise Exception(f'Patches identifier {p_id!r} is duplicated')
        unique.add(p_id)

    print("Finished")

    time_end = int(round(time.time() * 1000))
    print("\nElapsed: %sms\n" % (time_end-time_start))


if __name__ == '__main__':
    main()
