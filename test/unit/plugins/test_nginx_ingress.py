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

from kubemarine import demo
from kubemarine.core import errors


class EnrichmentValidation(unittest.TestCase):
    def install(self):
        self.inventory = demo.generate_inventory(**demo.ALLINONE)
        self.context = demo.create_silent_context()
        self.cert_renew = None
        self.cert_config = self.inventory.setdefault('plugins', {}).setdefault('nginx-ingress-controller', {})\
            .setdefault('controller', {}).setdefault('ssl', {}).setdefault('default-certificate', {})

    def cert_renew(self):
        self.inventory = demo.generate_inventory(**demo.ALLINONE)
        self.context = demo.create_silent_context(procedure='cert_renew')
        self.cert_renew = {}
        self.cert_config = self.cert_renew.setdefault('nginx-ingress-controller', {})

    def _new_cluster(self):
        return demo.new_cluster(self.inventory, procedure_inventory=self.cert_renew, context=self.context)

    def test_cert_both_data_paths_not_specified(self):
        for procedure in (self.install, self.cert_renew):
            with self.subTest(procedure.__name__):
                procedure()
                self.cert_config['unexpected_prop'] = 'value'
                with self.assertRaisesRegex(errors.FailException, r"'unexpected_prop' was unexpected"):
                    self._new_cluster()

    def test_cert_both_data_paths_specified(self):
        for procedure in (self.install, self.cert_renew):
            with self.subTest(procedure.__name__):
                procedure()
                self.cert_config['data'] = {'cert': 'c', 'key': 'k'}
                self.cert_config['paths'] = {'cert': 'c', 'key': 'k'}
                with self.assertRaisesRegex(errors.FailException, r"Number of properties is greater than the maximum of 1\. Property names: \['data', 'paths']"):
                    self._new_cluster()

    def test_cert_missed_cert(self):
        for procedure in (self.install, self.cert_renew):
            with self.subTest(procedure.__name__):
                procedure()
                self.cert_config['data'] = {'key': 'k'}
                with self.assertRaisesRegex(errors.FailException, r"'cert' is a required property"):
                    self._new_cluster()

    def test_cert_missed_key(self):
        for procedure in (self.install, self.cert_renew):
            with self.subTest(procedure.__name__):
                procedure()
                self.cert_config['paths'] = {'cert': 'c'}
                with self.assertRaisesRegex(errors.FailException, r"'key' is a required property"):
                    self._new_cluster()

    def test_cert_valid(self):
        for procedure in (self.install, self.cert_renew):
            with self.subTest(procedure.__name__):
                procedure()
                self.cert_config['data'] = {'cert': 'c', 'key': 'k'}
                self._new_cluster()


if __name__ == '__main__':
    unittest.main()
