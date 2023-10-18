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
    def setUp(self):
        self.inventory = demo.generate_inventory(**demo.MINIHA)
        self.context = demo.create_silent_context(['fake.yaml'], procedure='check_paas')
        self.check_paas = demo.generate_procedure_inventory('check_paas')
        self.check_paas['geo-monitor'] = {}

    def _new_cluster(self):
        return demo.new_cluster(self.inventory, procedure_inventory=self.check_paas, context=self.context)

    def test_geo_check_missed_namespace(self):
        self.check_paas['geo-monitor']['service'] = 's'
        with self.assertRaisesRegex(errors.FailException,  r"'namespace' is a required property"):
            self._new_cluster()

    def test_geo_check_missed_service(self):
        self.check_paas['geo-monitor']['namespace'] = 'n'
        with self.assertRaisesRegex(errors.FailException,  r"'service' is a required property"):
            self._new_cluster()

    def test_geo_check_valid(self):
        self.check_paas['geo-monitor']['service'] = 's'
        self.check_paas['geo-monitor']['namespace'] = 'n'
        self._new_cluster()


if __name__ == '__main__':
    unittest.main()
