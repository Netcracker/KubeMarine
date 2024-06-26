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

import unittest

from kubemarine.core import static
from kubemarine.procedures import config


class ProcedureConfigTest(unittest.TestCase):
    def test_make_config(self):
        """Does basic smoke test that kubemarine.procedures.config.make_config() exits successfully"""
        cfg = config.make_config()
        self.assertEqual(list(static.KUBERNETES_VERSIONS['compatibility_map']), list(cfg['kubernetes']))


if __name__ == '__main__':
    unittest.main()
