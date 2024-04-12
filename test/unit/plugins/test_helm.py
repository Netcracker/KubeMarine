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
import unittest
from test.unit import utils as test_utils

import yaml

from kubemarine import demo, plugins


class TestHelmProcessChartValues(test_utils.CommonTest):
    def setUp(self) -> None:
        self.chart_path = os.path.join(self.tmpdir, 'chart')
        os.makedirs(self.chart_path)
        self.chart_values = os.path.join(self.chart_path, 'values.yaml')

    def run(self, *args, **kwargs):
        with test_utils.temporary_directory(self):
            return super().run(*args, **kwargs)

    def test_values(self):
        self._set_chart_values({'var1': '0', 'var2': 'A'})
        self._test_process_chart_values(values={'var2': 'B'})
        actual_values = self._get_chart_values()
        self.assertEqual({'var1': '0', 'var2': 'B'}, actual_values,
                         "Unexpected content in values.yaml")

    def test_values_file(self):
        self._set_chart_values({'var1': '0', 'var2': 'A'})
        self._test_process_chart_values(values_file={'var1': '1'})
        actual_values = self._get_chart_values()
        self.assertEqual({'var1': '1', 'var2': 'A'}, actual_values,
                         "Unexpected content in values.yaml")

    def test_override_precedence(self):
        self._set_chart_values({'var1': '0', 'var2': 'A', 'var3': 'foo'})
        self._test_process_chart_values(values_file={'var1': '1', 'var2': 'B'}, values={'var2': 'C'})
        actual_values = self._get_chart_values()
        self.assertEqual({'var1': '1', 'var2': 'C', 'var3': 'foo'}, actual_values,
                         "Unexpected content in values.yaml")

    def _test_process_chart_values(self, values_file: dict = None, values: dict = None):
        inventory = demo.generate_inventory(**demo.ALLINONE)
        procedure = self._prepare_helm_procedure(values_file=values_file, values=values)
        self._procedures(inventory, 'my_plugin').append(procedure)

        cluster = demo.new_cluster(inventory)
        enriched_config = self._procedures(cluster.inventory, 'my_plugin')[0]['helm']

        plugins.process_chart_values(enriched_config, self.chart_path)

    def _procedures(self, inventory: dict, plugin_name: str):
        return inventory.setdefault('plugins', {}).setdefault(plugin_name, {})\
            .setdefault('installation', {}).setdefault('procedures', [])

    def _get_chart_values(self):
        with open(self.chart_values, 'r', encoding='utf-8') as stream:
            return yaml.safe_load(stream.read())

    def _set_chart_values(self, values: dict):
        with open(self.chart_values, 'w', encoding='utf-8') as stream:
            stream.write(yaml.dump(values))

    def _prepare_helm_procedure(self, values_file: dict = None, values: dict = None) -> dict:
        config = {
            'chart_path': __file__,
        }
        if values is not None:
            config['values'] = values
        if values_file is not None:
            override = os.path.join(self.tmpdir, 'override.yaml')
            with open(override, 'w', encoding='utf-8') as stream:
                stream.write(yaml.dump(values_file))

            config['values_file'] = override

        return {'helm': config}


if __name__ == '__main__':
    unittest.main()
