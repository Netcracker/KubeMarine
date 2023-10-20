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

import logging
import os
import tempfile
import unittest
from typing import List
from unittest import mock

import yaml

from kubemarine import demo, thirdparties
from kubemarine.core import utils, log, static
from kubemarine.procedures import restore, backup
from test.unit import utils as test_utils


class RestoreEnrichmentTest(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.inventory = demo.generate_inventory(**demo.FULLHA_KEEPALIVED)

        self.context = self._create_context(['--without-act'])
        utils.prepare_dump_directory(self.context['execution_arguments']['dump_location'])

        self.restore_tmpdir = os.path.join(self.tmpdir.name, 'restore_test')
        os.mkdir(self.restore_tmpdir)

        self.backup_location = os.path.join(self.tmpdir.name, 'backup.tar.gz')
        self.restore = demo.generate_procedure_inventory('restore')
        self.restore['backup_location'] = self.backup_location

    def tearDown(self):
        logger = logging.getLogger("k8s.fake.local")
        for h in logger.handlers:
            if isinstance(h, log.FileHandlerWithHeader):
                h.close()
        self.tmpdir.cleanup()

    def _create_context(self, args: List[str]) -> dict:
        context = demo.create_silent_context(['fake_path.yaml'] + args, procedure='restore')

        args = context['execution_arguments']
        args['disable_dump'] = False
        args['dump_location'] = self.tmpdir.name

        return context

    def _run(self) -> demo.FakeResources:
        resources = demo.FakeResources(self.context, self.inventory,
                                       procedure_inventory=self.restore,
                                       nodes_context=demo.generate_nodes_context(self.inventory))

        restore.RestoreFlow()._run(resources)
        return resources

    def _pack_descriptor(self, backup_descriptor: dict):
        with utils.open_external(os.path.join(self.restore_tmpdir, 'descriptor.yaml'), 'w') as output:
            output.write(yaml.dump(backup_descriptor))

    def _pack_data(self):
        backup.pack_to_tgz(self.backup_location, self.restore_tmpdir)

    def test_enrich_and_finalize_inventory_kubernetes_version(self):
        self.inventory['services'].setdefault('kubeadm', {})['kubernetesVersion'] = 'v1.28.0'
        descriptor = {'kubernetes': {'version': 'v1.27.4'}}
        self._pack_descriptor(descriptor)
        self._pack_data()

        resources = self._run()
        cluster = resources.last_cluster

        self.assertEqual('v1.27.4', cluster.inventory['services']['kubeadm']['kubernetesVersion'],
                         "Kubernetes version was not restored from backup")

        test_utils.stub_associations_packages(cluster, {})
        finalized_inventory = cluster.make_finalized_inventory()
        self.assertEqual('v1.27.4', finalized_inventory['services']['kubeadm']['kubernetesVersion'],
                         "Kubernetes version was not restored from backup")

        self.assertEqual('v1.27.4', resources.stored_inventory['services']['kubeadm']['kubernetesVersion'],
                         "Kubernetes version was not restored from backup")

    def test_enrich_and_finalize_inventory_thirdparties(self):
        thirdparties_section = self.inventory['services'].setdefault('thirdparties', {})
        thirdparties_section['/usr/bin/kubectl'] = {
            'source': 'kubectl-new',
        }
        thirdparties_section['/usr/bin/kubeadm'] = 'kubeadm-new'

        restore_thirdparties = self.restore.setdefault('restore_plan', {}).setdefault('thirdparties', {})
        restore_thirdparties['/usr/bin/kubectl'] = {
            'source': 'kubectl-old',
            'sha1': 'kubectl-sha1-old'
        }
        restore_thirdparties['/usr/bin/kubeadm'] = {
            'source': 'kubeadm-old',
        }
        restore_thirdparties['/usr/bin/kubelet'] = {
            'source': 'kubelet-old',
        }

        all_thirdparties = set(static.DEFAULTS['services']['thirdparties'])

        self.context = self._create_context(['--tasks', 'restore.thirdparties'])
        self._pack_descriptor({})
        self._pack_data()

        with mock.patch.object(thirdparties, thirdparties.install_thirdparty.__name__) as install_thirdparty:
            resources = self._run()
        cluster = resources.last_cluster

        thirdparties_section = cluster.inventory['services']['thirdparties']
        self.assertEqual(all_thirdparties, set(thirdparties_section.keys()))
        self.assertEqual('kubectl-old', thirdparties_section['/usr/bin/kubectl']['source'])
        self.assertEqual('kubectl-sha1-old', thirdparties_section['/usr/bin/kubectl']['sha1'])
        self.assertEqual('kubeadm-old', thirdparties_section['/usr/bin/kubeadm']['source'])
        self.assertIsNone(thirdparties_section['/usr/bin/kubeadm'].get('sha1'))
        self.assertEqual('kubelet-old', thirdparties_section['/usr/bin/kubelet']['source'])
        self.assertIsNone(thirdparties_section['/usr/bin/kubelet'].get('sha1'))

        test_utils.stub_associations_packages(cluster, {})
        finalized_inventory = cluster.make_finalized_inventory()
        thirdparties_section = finalized_inventory['services']['thirdparties']

        self.assertEqual(all_thirdparties, set(thirdparties_section.keys()))
        self.assertEqual('kubectl-old', thirdparties_section['/usr/bin/kubectl']['source'])
        self.assertEqual('kubectl-sha1-old', thirdparties_section['/usr/bin/kubectl']['sha1'])
        self.assertEqual('kubeadm-old', thirdparties_section['/usr/bin/kubeadm']['source'])
        self.assertIsNone(thirdparties_section['/usr/bin/kubeadm'].get('sha1'))
        self.assertEqual('kubelet-old', thirdparties_section['/usr/bin/kubelet']['source'])
        self.assertIsNone(thirdparties_section['/usr/bin/kubelet'].get('sha1'))

        thirdparties_section = resources.stored_inventory['services']['thirdparties']
        self.assertEqual({'/usr/bin/kubectl', '/usr/bin/kubelet', '/usr/bin/kubeadm'},
                         set(thirdparties_section.keys()))
        self.assertEqual('kubectl-old', thirdparties_section['/usr/bin/kubectl']['source'])
        self.assertEqual('kubectl-sha1-old', thirdparties_section['/usr/bin/kubectl']['sha1'])
        self.assertEqual('kubeadm-old', thirdparties_section['/usr/bin/kubeadm']['source'])
        self.assertIsNone(thirdparties_section['/usr/bin/kubeadm'].get('sha1'))
        self.assertEqual('kubelet-old', thirdparties_section['/usr/bin/kubelet']['source'])
        self.assertIsNone(thirdparties_section['/usr/bin/kubelet'].get('sha1'))


if __name__ == '__main__':
    unittest.main()
