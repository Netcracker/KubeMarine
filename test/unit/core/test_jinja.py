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

import json
import re
import unittest
from test.unit import utils as test_utils

import yaml

from kubemarine import demo


class TestCompilation(unittest.TestCase):
    def test_escapes(self):
        inventory = demo.generate_inventory(**demo.ALLINONE)
        inventory['values'] = {
            'var1': "{{ '{{ .Name }}' }}",
            'var2': "{% raw %}{{ .Name }}{% endraw %}",
            'var3': '{% raw %}{{ raw1 }}{% endraw %}text1{% raw %}{{ raw2 }}{% endraw %}text2',
            'var4': 'A',
            'var5': '{% raw %}{{ raw1 }}{% endraw %}{{ values.var4 }}{% raw %}{{ raw2 }}{% endraw %}{{ values.var4 }}',
            'var6': '{% raw %}{{ raw1 }}{% endraw %}{{ values.var2 }}{% raw %}{{ raw2 }}{% endraw %}{{ values.var2 }}',
        }

        def test(cluster_: demo.FakeKubernetesCluster):
            values = cluster_.inventory['values']
            self.assertEqual('{{ .Name }}', values['var1'])
            self.assertEqual('{{ .Name }}', values['var2'])
            self.assertEqual('{{ raw1 }}text1{{ raw2 }}text2', values['var3'])
            self.assertEqual('{{ raw1 }}A{{ raw2 }}A', values['var5'])
            self.assertEqual('{{ raw1 }}{{ .Name }}{{ raw2 }}{{ .Name }}', values['var6'])

        cluster = demo.new_cluster(inventory)
        test(cluster)

        cluster = demo.new_cluster(test_utils.make_finalized_inventory(cluster))
        test(cluster)

    def test_recursive_filters(self):
        inventory = demo.generate_inventory(**demo.ALLINONE)
        inventory['values'] = {
            'var1': "{{ values.template | b64encode | b64decode | upper }}",
            'var2': "{{ (values.int1 | int) + (values.int2 | int) }}",
            'var3': "{{ '{{ values.TEST }}' | b64encode | b64decode | lower }}",
            'var4': "{{ '{{ values.TEST }}' | lower }}",
            'template': '{{ "text" }}',
            'int1': '{{ 1 }}',
            'int2': '{{ 2 }}',
            'test': 'unexpected'
        }

        cluster = demo.new_cluster(inventory)
        values = cluster.inventory['values']

        self.assertEqual('TEXT', values['var1'])
        self.assertEqual('3', values['var2'])
        self.assertEqual('{{ values.test }}', values['var3'])
        self.assertEqual('{{ values.test }}', values['var4'])

    def test_not_existing_variables(self):
        inventory = demo.generate_inventory(**demo.ALLINONE)
        inventory['values'] = {
            'var1': '{{ values.notexists | default("not exists") }}',
            'var2': [],
            'var3': '{{ values.var2[0] | lower }}',
            'var4': '{{ values.var2[:10][0] | default("not exists") }}',
        }

        cluster = demo.new_cluster(inventory)
        values = cluster.inventory['values']

        self.assertEqual('not exists', values['var1'])
        self.assertEqual('', values['var3'])
        self.assertEqual('not exists', values['var4'])

    def test_mappings(self):
        inventory = demo.generate_inventory(**demo.ALLINONE)
        template_map = {
            'foo': 'bar', 'array': ['{{ values.ref }}', 2],
        }
        expected_map = {
            'foo': 'bar', 'array': ['text', 2],
        }
        inventory['values'] = {
            'var1': '{{ values.map }}',
            'var2': '{{ values.map | tojson }}',
            'map': template_map,
            'var3': '{{ values.map | toyaml }}',
            'var4': '{{ values is mapping }}',
            'var5': '{{ "ref" in values }}',
            'var6': '{{ "missed" in values }}',
            'ref': 'text',
        }

        cluster = demo.new_cluster(inventory)
        values = cluster.inventory['values']

        self.assertEqual("{'foo': 'bar', 'array': ['text', 2]}", values['var1'])
        self.assertEqual(expected_map, json.loads(values['var2']))
        self.assertEqual(expected_map, yaml.safe_load(values['var3']))
        self.assertEqual('True', values['var4'])
        self.assertEqual('True', values['var5'])
        self.assertEqual('False', values['var6'])

    def test_sequences(self):
        inventory = demo.generate_inventory(**demo.ALLINONE)
        template_list = [1, 2, {'3': '{{ values.ref }}'}, 4, 5, 6, 7, 8, 9]
        expected_list = [1, 2, {'3': 'text'}, 4, 5, 6, 7, 8, 9]
        inventory['values'] = {
            'list': template_list,
            'var1': '{{ values.list }}',
            'var2': '{{ values.list | tojson }}',
            'var3': '{{ values.list | toyaml }}',
            'var4': '{{ values.list is sequence }}',
            'var5': '{{ 5 in values.list }}',
            'var6': '{{ 0 in values.list }}',
            'ref': 'text',
        }

        cluster = demo.new_cluster(inventory)
        values = cluster.inventory['values']

        self.assertEqual("[1, 2, {'3': 'text'}, 4, 5, 6, 7, 8, 9]", values['var1'])
        self.assertEqual(expected_list, json.loads(values['var2']))
        self.assertEqual(expected_list, yaml.safe_load(values['var3']))
        self.assertEqual('True', values['var4'])
        self.assertEqual('True', values['var5'])
        self.assertEqual('False', values['var6'])

    def test_slices(self):
        inventory = demo.generate_inventory(**demo.ALLINONE)
        template_list = [1, 2, {'3': '{{ values.ref }}'}, 4, 5, 6, 7, 8, 9]
        expected_slice = [1, {'3': 'text'}]
        inventory['values'] = {
            'list': template_list,
            'var1': '{{ values.list[:4:2] }}',
            'var2': '{{ values.list[:4:2] | tojson }}',
            'var3': '{{ values.list[:4:2] | toyaml }}',
            'var4': '{{ values.list[:4:2] is sequence }}',
            'var5': '{{ 1 in values.list[:4:2] }}',
            'var6': '{{ 2 in values.list[:4:2] }}',
            'var7': '{{ values.list[:6:2][1:][1] }}',
            'ref': 'text',
        }

        cluster = demo.new_cluster(inventory)
        values = cluster.inventory['values']

        self.assertEqual("[1, {'3': 'text'}]", values['var1'])
        self.assertEqual(expected_slice, json.loads(values['var2']))
        self.assertEqual(expected_slice, yaml.safe_load(values['var3']))
        self.assertEqual('True', values['var4'])
        self.assertEqual('True', values['var5'])
        self.assertEqual('False', values['var6'])
        self.assertEqual('5', values['var7'])

    def test_redefine_inventory_section(self):
        inventory = demo.generate_inventory(**demo.ALLINONE)
        inventory['cluster_name'] = 'test-cluster'
        inventory['values'] = {
            'var1': '{% set cluster_name = "redefined" %}{{ cluster_name }}',
            'var2': '{{ cluster_name }}',
        }

        cluster = demo.new_cluster(inventory)
        values = cluster.inventory['values']

        self.assertEqual("redefined", values['var1'])
        self.assertEqual("test-cluster", values['var2'])

    def test_cyclic_references(self):
        inventory = demo.generate_inventory(**demo.ALLINONE)
        inventory['values'] = {
            'var0': '{{ values.var1 }}',
            'var1': '{{ values.var3 }}',
            'var2': '{{ values.var1 }}',
            'var3': '{{ values.var2 }}',
        }

        with test_utils.assert_raises_regex(self, ValueError, re.escape(
                "Cyclic dynamic variables in inventory['values']['var1'] -> ['values']['var3'] -> ['values']['var2']")):
            demo.new_cluster(inventory)

    def test_cyclic_references_proxy_types(self):
        inventory = demo.generate_inventory(**demo.ALLINONE)
        inventory['values'] = {
            'var1': [1, '{{ values.var3 }}', '{{ values.var2 }}', 4],
            'var2': '{{ values.var1[1] }}',
            'var3': '{{ values.var1[1:][:2][1] }}',
        }

        with test_utils.assert_raises_regex(self, ValueError, re.escape(
                "Cyclic dynamic variables in inventory"
                "['values']['var1'][1] -> ['values']['var3'] -> ['values']['var1'][2] -> ['values']['var2']")):
            demo.new_cluster(inventory)


if __name__ == '__main__':
    unittest.main()
