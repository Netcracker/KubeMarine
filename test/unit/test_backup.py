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

import gzip
import unittest
from contextlib import contextmanager
from pathlib import Path
from textwrap import dedent
from typing import Optional
from unittest import mock
from test.unit import utils as test_utils

from kubemarine import demo
from kubemarine.core import utils, flow
from kubemarine.procedures import backup


class TestBackupTasks(test_utils.CommonTest):
    def setUp(self):
        self.inventory = demo.generate_inventory(**demo.FULLHA_KEEPALIVED)
        self.hosts = [node['address'] for node in self.inventory['nodes']]

        self.context = demo.create_silent_context(['fake.yaml'], procedure='backup')

        self.args = self.context['execution_arguments']
        self.args['disable_dump'] = False
        self.args['dump_location'] = self.tmpdir
        utils.prepare_dump_directory(self.context)

        self.fake_shell = demo.FakeShell()
        self.resources: Optional[demo.FakeResources] = None

    def run(self, *args, **kwargs):
        with test_utils.temporary_directory(self):
            return super().run(*args, **kwargs)

    def _run(self, procedure_inventory: dict):
        self.resources = test_utils.FakeResources(self.context, self.inventory,
                                                  procedure_inventory=procedure_inventory,
                                                  nodes_context=demo.generate_nodes_context(self.inventory),
                                                  fake_shell=self.fake_shell)

        flow.run_actions(self.resources, [backup.BackupAction()])

    def test_export_whole_kubernetes(self):
        self.args['tasks'] = 'export.kubernetes'
        self._stub_load_namespaces()
        self._stub_load_resources()

        backup_all_procedure = demo.generate_procedure_inventory('backup')
        backup_all_procedure.setdefault('backup_plan', {}).setdefault('kubernetes', {})\
            .setdefault('namespaced_resources', {}).setdefault('resources', 'all')
        backup_all_procedure.setdefault('backup_plan', {}).setdefault('kubernetes', {}) \
            .setdefault('nonnamespaced_resources', 'all')

        with self._mock_download():
            self._run(backup_all_procedure)

        descriptor = self.resources.cluster_if_initialized().context['backup_descriptor']['kubernetes']['resources']
        self.assertEqual({'kube-system': ['configmaps', 'configmaps.example.com', 'roles.rbac.authorization.k8s.io']},
                         descriptor.get('namespaced'),
                         "Not expected resulting list of namespaced resources")
        self.assertEqual(['nodes'], descriptor.get('nonnamespaced'),
                         "Not expected resulting list of non-namespaced resources")

        resources_path = Path(self.tmpdir) / 'dump' / 'backup' / 'kubernetes_resources'
        actual_files = {str(p.relative_to(resources_path)) for p in resources_path.glob("**/*.yaml")}
        expected_files = {str(Path(p)) for p in ['nodes.yaml', 'kube-system/configmaps.yaml',
                                                 'kube-system/configmaps.example.com.yaml',
                                                 'kube-system/roles.rbac.authorization.k8s.io.yaml']}
        self.assertEqual(expected_files, actual_files, "Not expected list of files")

        expected_context = self._parse_yaml(dedent(
            '''\
            apiVersion: v1
            items:
            - apiVersion: v1
              kind: Node
              metadata:
                name: control-plane-1
            kind: List
            metadata:
              resourceVersion: ""
            '''
        ))
        actual_content = self._parse_yaml(utils.read_external(str(resources_path / 'nodes.yaml')))
        self.assertEqual(expected_context, actual_content,
                         f"Data in file 'nodes.yaml' is not expected")

        expected_context = self._parse_yaml(dedent(
            '''\
            apiVersion: v1
            items:
            - apiVersion: v1
              data:
                key: =
              kind: ConfigMap
              metadata:
                name: calico-config
            - apiVersion: v1
              data:
                Corefile: |
                  .:53 {
                  }
                Hosts: |
                  127.0.0.1 localhost localhost.localdomain
            
                  10.101.2.1  k8s.fake.local control-plain
              kind: ConfigMap
              metadata:
                name: coredns
            kind: List
            metadata:
              resourceVersion: ""
            '''
        ))
        actual_content = self._parse_yaml(utils.read_external(str(resources_path / 'kube-system/configmaps.yaml')))
        expected_special_symbol = expected_context['items'][0]['data'].pop('key')
        actual_special_symbol = actual_content['items'][0]['data'].pop('key')
        self.assertEqual(expected_special_symbol.value, actual_special_symbol.value,
                         "Failed to compare special TaggedScalar")
        self.assertEqual(expected_context, actual_content,
                         f"Data in file 'kube-system/configmaps.yaml' is not expected")

        expected_context = self._parse_yaml(dedent(
            '''\
            apiVersion: v1
            items:
            - apiVersion: example.com/v1
              data:
                key: value
              kind: ConfigMap
              metadata:
                name: example-configmap
            kind: List
            metadata:
              resourceVersion: ""
            '''
        ))
        actual_content = self._parse_yaml(utils.read_external(
            str(resources_path / 'kube-system/configmaps.example.com.yaml')))
        self.assertEqual(expected_context, actual_content,
                         f"Data in file 'kube-system/configmaps.example.com.yaml' is not expected")

        expected_context = self._parse_yaml(dedent(
            '''\
            apiVersion: v1
            items:
            - apiVersion: rbac.authorization.k8s.io/v1
              kind: Role
              metadata:
                name: kube-proxy
              rules: []
            kind: List
            metadata:
              resourceVersion: ""
            '''
        ))
        actual_content = self._parse_yaml(utils.read_external(
            str(resources_path / 'kube-system/roles.rbac.authorization.k8s.io.yaml')))
        self.assertEqual(expected_context, actual_content,
                         f"Data in file 'kube-system/roles.rbac.authorization.k8s.io.yaml' is not expected")

    def test_export_default_kubernetes(self):
        self.args['tasks'] = 'export.kubernetes'
        self._stub_load_namespaces()
        self._stub_load_resources()

        backup_all_procedure = demo.generate_procedure_inventory('backup')

        with self._mock_download():
            self._run(backup_all_procedure)

        descriptor = self.resources.cluster_if_initialized().context['backup_descriptor']['kubernetes']['resources']
        self.assertEqual({}, descriptor, "Not expected resulting list of resources")

        resources_path = Path(self.tmpdir) / 'dump' / 'backup' / 'kubernetes_resources'
        actual_files = {str(p.relative_to(resources_path)) for p in resources_path.glob("**/*.yaml")}
        self.assertFalse(actual_files, "List of files is not empty")

    def _parse_yaml(self, data: str):
        return utils.yaml_structure_preserver().load(data)

    def _stub_load_namespaces(self):
        results = demo.create_hosts_result(self.hosts, stdout='\n'.join(['default', 'kube-system']))
        self.fake_shell.add(results, 'sudo',
                            ['kubectl get ns -o jsonpath=\'{range .items[*]}{.metadata.name}{"\\n"}{end}\''])

    def _stub_load_resources(self):
        results = demo.create_hosts_result(self.hosts, stdout=dedent(
            '''\
            NAME         SHORTNAMES   APIVERSION                     NAMESPACED   KIND
            configmaps   cm           v1                             true         ConfigMap
            configmaps                example.com/v1                 true         ConfigMap
            events       ev           v1                             true         Event
            events       ev           events.k8s.io/v1               true         Event
            roles                     rbac.authorization.k8s.io/v1   true         Role
            '''
        ))
        self.fake_shell.add(results, 'sudo',
                            ['kubectl api-resources --verbs=list --sort-by=name --namespaced'])

        results = demo.create_hosts_result(self.hosts, stdout=dedent(
            '''\
            NAME         SHORTNAMES   APIVERSION   NAMESPACED   KIND
            namespaces   ns           v1           false        Namespace
            nodes        no           v1           false        Node
            '''
        ))
        self.fake_shell.add(results, 'sudo',
                            ['kubectl api-resources --verbs=list --sort-by=name --namespaced=false'])

    @contextmanager
    def _mock_download(self):
        download_orig = backup.ExportKubernetesDownloader._download  # pylint: disable=protected-access

        def download_stub(location: str, data: str):
            with gzip.open(location, 'wt', encoding='utf-8') as f:
                f.write(data)

        def download_mocked(_, task: backup.DownloaderPayload, temp_local_filepath: str) -> None:
            namespace = task.namespace
            resources = task.resources
            if namespace == 'kube-system' and resources == ['configmaps', 'configmaps.example.com',
                                                            'roles.rbac.authorization.k8s.io']:
                download_stub(temp_local_filepath, dedent(
                    '''\
                    apiVersion: v1
                    items:
                    - apiVersion: v1
                      data:
                        key: =
                      kind: ConfigMap
                      metadata:
                        name: calico-config
                    - apiVersion: v1
                      data:
                        Corefile: |
                          .:53 {
                          }
                        Hosts: |
                          127.0.0.1 localhost localhost.localdomain
                    
                          10.101.2.1  k8s.fake.local control-plain
                      kind: ConfigMap
                      metadata:
                        name: coredns
                    - apiVersion: example.com/v1
                      data:
                        key: value
                      kind: ConfigMap
                      metadata:
                        name: example-configmap
                    - apiVersion: rbac.authorization.k8s.io/v1
                      kind: Role
                      metadata:
                        name: kube-proxy
                      rules: []
                    kind: List
                    metadata:
                      resourceVersion: ""
                    '''
                ))
            elif namespace == 'default' and resources == ['configmaps', 'configmaps.example.com',
                                                          'roles.rbac.authorization.k8s.io']:
                download_stub(temp_local_filepath, '')
            elif namespace is None and resources == ['namespaces', 'nodes']:
                download_stub(temp_local_filepath, dedent(
                    '''\
                    apiVersion: v1
                    items:
                    - apiVersion: v1
                      kind: Node
                      metadata:
                        name: control-plane-1
                    kind: List
                    metadata:
                      resourceVersion: ""
                    '''
                ))
            else:
                raise Exception(f"Unexpected resources {resources} to download for namespace {namespace}")

        with mock.patch.object(backup.ExportKubernetesDownloader, download_orig.__name__,
                               new=download_mocked):
            yield


if __name__ == '__main__':
    unittest.main()
