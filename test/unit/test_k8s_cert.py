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

from kubemarine import demo

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


if __name__ == '__main__':
    unittest.main()
