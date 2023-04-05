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

import os.path
import tempfile
import unittest

import yaml

from kubemarine import demo, plugins


class TestHelm(unittest.TestCase):
    def test_process_chart_values_override_precedence(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            chart = os.path.join(tmpdir, 'chart')
            values_file = os.path.join(chart, 'values.yaml')
            os.makedirs(chart)
            with open(values_file, 'w') as stream:
                stream.write(yaml.dump({'var1': '0', 'var2': 'A', 'var3': 'foo'}))

            override = os.path.join(tmpdir, 'override.yaml')
            with open(override, 'w') as stream:
                stream.write(yaml.dump({'var1': '1', 'var2': 'B'}))

            inventory = demo.generate_inventory(**demo.ALLINONE)
            self._procedures(inventory, 'my_plugin').append({
                'helm': {
                    'chart_path': __file__,
                    'values_file': override,
                    'values': {
                        'var2': 'C'
                    }
                }
            })
            cluster = demo.new_cluster(inventory)
            enriched_config = self._procedures(cluster.inventory, 'my_plugin')[0]['helm']

            plugins.process_chart_values(enriched_config, chart)

            with open(values_file, 'r') as stream:
                actual_values = yaml.safe_load(stream.read())

            self.assertEqual({'var1': '1', 'var2': 'C', 'var3': 'foo'}, actual_values,
                             "Unexpected content in values.yaml")

    def _procedures(self, inventory: dict, plugin_name: str):
        return inventory.setdefault('plugins', {}).setdefault(plugin_name, {})\
            .setdefault('installation', {}).setdefault('procedures', [])


if __name__ == '__main__':
    unittest.main()
