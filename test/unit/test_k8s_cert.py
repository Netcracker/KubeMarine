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

import unittest
from copy import deepcopy
from unittest import mock
from test.unit import utils as test_utils

from kubemarine import demo, plugins
from kubemarine.core import flow
from kubemarine.plugins import nginx_ingress
from kubemarine.procedures import cert_renew

supported_k8s_certs = ["apiserver", "apiserver-etcd-client", "apiserver-kubelet-client",
                       "etcd-healthcheck-client", "etcd-peer", "etcd-server",
                       "admin.conf", "controller-manager.conf", "scheduler.conf",
                       "front-proxy-client"]


class K8sCertTest(unittest.TestCase):
    def setUp(self):
        self.inventory = demo.generate_inventory(**demo.ALLINONE)
        self.context = demo.create_silent_context(['fake.yaml'], procedure='cert_renew')
        self.cert_renew = demo.generate_procedure_inventory('cert_renew')
        self.cert_renew['kubernetes'] = {
            'cert-list': []
        }

    def _new_cluster(self):
        return demo.new_cluster(deepcopy(self.inventory), procedure_inventory=deepcopy(self.cert_renew),
                                context=self.context)

    def _cert_list(self):
        return self.cert_renew['kubernetes']['cert-list']

    def test_certs_verify_succeeds(self):
        self._cert_list().extend(supported_k8s_certs)
        self._new_cluster()

    def test_certs_verify_fails(self):
        self._cert_list().append("bad test")
        with self.assertRaisesRegex(Exception, r"Value should be one of \[.*]"):
            self._new_cluster()

    def test_single_all_verify_succeeds(self):
        self._cert_list().append("all")
        self._new_cluster()

    def test_single_all_verify_fails(self):
        self._cert_list().extend(["all", "apiserver"])
        with self.assertRaisesRegex(Exception, "Found 'all' in certs list, but it is not single"):
            self._new_cluster()

    def test_none_cert_list(self):
        self.cert_renew['kubernetes']['cert-list'] = None
        with self.assertRaisesRegex(Exception, "Actual instance type is 'null'. Expected: 'array'"):
            self._new_cluster()

    def test_non_list_cert_list(self):
        self.cert_renew['kubernetes']['cert-list'] = "value"
        with self.assertRaisesRegex(Exception, "Actual instance type is 'string'. Expected: 'array'"):
            self._new_cluster()

    def test_empty_cert_list(self):
        self.cert_renew['kubernetes']['cert-list'] = []
        with self.assertRaisesRegex(Exception, "Number of items equal to 0 is less than the minimum of 1"):
            self._new_cluster()


class IngressNginxCertTest(unittest.TestCase):
    def setUp(self):
        self.inventory = demo.generate_inventory(**demo.ALLINONE)
        self.plugin = self.inventory.setdefault('plugins', {}).setdefault('nginx-ingress-controller', {})
        self.context = demo.create_silent_context(['fake.yaml', '--tasks', 'nginx_ingress_controller'],
                                                  procedure='cert_renew')
        self.cert_renew = demo.generate_procedure_inventory('cert_renew')

    def _inventory_cert(self) -> dict:
        return self.plugin.setdefault('controller', {}).setdefault('ssl', {})\
            .setdefault('default-certificate', {})

    def _procedure_cert(self) -> dict:
        return self.cert_renew.setdefault('nginx-ingress-controller', {})

    def _run_and_check(self, called: bool) -> demo.FakeResources:
        with mock.patch.object(plugins, plugins.install_plugin.__name__) as run, test_utils.unwrap_fail():
            resources = test_utils.FakeResources(self.context, self.inventory,
                                                 procedure_inventory=self.cert_renew,
                                                 nodes_context=demo.generate_nodes_context(self.inventory))
            try:
                flow.run_actions(resources, [cert_renew.CertRenewAction()])
            finally:
                self.assertEqual(called, run.called)

        return resources

    def test_enrich_and_finalize_inventory(self):
        self.plugin['install'] = True
        self._inventory_cert()['data'] = {'cert': 'cert-old', 'key': 'key-old'}
        self._procedure_cert()['data'] = {'cert': 'cert-new', 'key': 'key-new'}

        resources = self._run_and_check(True)

        cert = resources.working_inventory['plugins']['nginx-ingress-controller']['controller']['ssl']['default-certificate']
        self.assertEqual({'data': {'cert': 'cert-new', 'key': 'key-new'}}, cert,
                         "Certificate data are enriched incorrectly")

        cert = resources.finalized_inventory['plugins']['nginx-ingress-controller']['controller']['ssl']['default-certificate']
        self.assertEqual({'data': {'cert': 'cert-new', 'key': 'key-new'}}, cert,
                         "Certificate data are enriched incorrectly")

        cert = resources.inventory()['plugins']['nginx-ingress-controller']['controller']['ssl']['default-certificate']
        self.assertEqual({'data': {'cert': 'cert-new', 'key': 'key-new'}}, cert,
                         "Certificate data are enriched incorrectly")

    def test_skip_renew_nginx_ingress(self):
        self.plugin['install'] = True
        self._inventory_cert()['paths'] = {'cert': 'c', 'key': 'k'}
        self._run_and_check(False)

    def test_run_renew_nginx_ingress_same_paths(self):
        self.plugin['install'] = True
        self._inventory_cert()['paths'] = {'cert': 'c', 'key': 'k'}
        self._procedure_cert()['paths'] = {'cert': 'c', 'key': 'k'}
        # Although nothing changes in the configuration, something may change in the files content
        self._run_and_check(True)

    def test_fail_renew_nginx_ingress_plugin_not_installed_template(self):
        self.inventory['values'] = {'plugins': {'install': False}}
        self.plugin['install'] = '{{ values.plugins.install }}'
        self._procedure_cert()['paths'] = {'cert': 'c', 'key': 'k'}
        # Although nothing changes in the configuration, something may change in the files content
        with self.assertRaisesRegex(Exception, nginx_ingress.ERROR_CERT_RENEW_NOT_INSTALLED):
            self._run_and_check(False)


if __name__ == '__main__':
    unittest.main()
