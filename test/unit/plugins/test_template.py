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
import os
import unittest
from test.unit import utils as test_utils

from kubemarine import demo, plugins
from kubemarine.core import errors, utils
from kubemarine.plugins import verify_template, apply_template


class TestTemplate(test_utils.CommonTest):

    def test_verify_missed_source(self):
        for procedure_type in ('template', 'config'):
            inventory = demo.generate_inventory(**demo.ALLINONE)
            inventory['plugins'] = {'custom': {'installation': {'procedures': [
                {procedure_type: {'not as source': 'something'}}
            ]}}}
            with self.assertRaisesRegex(errors.FailException, r"'source' is a required property"):
                demo.new_cluster(inventory)

    def test_verify_template(self):
        test_cases = [
            {
                "name": "One yaml template",
                "source": f"{__file__}/../test_templates/test_template1.yaml",
                "valid": True,
            },
            {
                "name": "Wildcard path matching three yaml templates",
                "source": f"{__file__}/../test_templates/*.yaml",
                "valid": True,
            },
            {
                "name": "Directory wildcard path matching two yaml templates",
                "source": f"{__file__}/../test_templates/*",
                "valid": True,
            },
            {
                "name": "Wildcard path matching zero templates",
                "source": f"{__file__}/../test_templates/*.conf",
                "valid": False,
            },
            {
                "name": "Path to non-existent template",
                "source": f"{__file__}/../test_templates/template.conf",
                "valid": False,
            },
        ]

        for tc in test_cases:
            # Run the test
            with self.subTest(tc["name"]):
                # Create new test config with the source value
                config = {"source": tc["source"]}

                if tc["valid"]:
                    # If test case is valid just run the function
                    verify_template(None, config)
                else:
                    # If test case is not valid check for exception raise
                    self.assertRaises(
                        Exception,
                        verify_template,
                        None, config
                    )

    def test_apply_template(self):
        test_cases = [
            {
                "name": "One yaml template",
                "apply_files": ["test_template1.yaml"],
                "source": f"{__file__}/../test_templates/test_template1.yaml",
            },
            {
                "name": "Wildcard path matching three yaml templates",
                "apply_files": ["test_template1.yaml", "test_template2.yaml", "test_template3.yaml"],
                "source": f"{__file__}/../test_templates/*.yaml",
            },
            {
                "name": "Directory wildcard path matching three yaml templates",
                "apply_files": ["test_template1.yaml", "test_template2.yaml", "test_template3.yaml"],
                "source": f"{__file__}/../test_templates/*",
            },
        ]

        for tc in test_cases:
            # Run the test
            with self.subTest(tc["name"]):
                # Create new fake cluster
                cluster = demo.new_cluster(
                    demo.generate_inventory(**demo.FULLHA))
                # Create new test config with the source value
                config = {
                    "source": tc["source"],
                }

                for file in tc["apply_files"]:
                    result = demo.create_nodegroup_result(cluster.nodes["control-plane"], hide=False)
                    cluster.fake_shell.add(result, "sudo", [f"kubectl apply -f /etc/kubernetes/{file}"], usage_limit=1)

                # If test case is valid just run the function
                apply_template(cluster, config)

                for file in tc["apply_files"]:
                    cnt = 0
                    for host in cluster.nodes['control-plane'].get_hosts():
                        history = cluster.fake_shell.history_find(host, "sudo", [f"kubectl apply -f /etc/kubernetes/{file}"])
                        if len(history) == 1 and history[0]["used_times"] == 1:
                            cnt += 1
                    self.assertEqual(1, cnt)

    @test_utils.temporary_directory
    def test_compile_template(self):
        template_file = os.path.join(self.tmpdir, 'template.yaml.j2')
        with utils.open_external(template_file, 'w') as t:
            t.write('Compiled: {{ plugins.my_plugin.compiled }}')

        inventory = demo.generate_inventory(**demo.ALLINONE)

        inventory['plugins'] = {'my_plugin': {
            'compiled': '{{ "{{ Yes }}" }}',
            'install': True,
            'installation': {'procedures': [{'template': template_file}]}
        }}

        cluster = demo.new_cluster(inventory)

        result = demo.create_nodegroup_result(cluster.nodes["control-plane"], hide=False)
        cluster.fake_shell.add(result, "sudo", [f"kubectl apply -f /etc/kubernetes/template.yaml"], usage_limit=1)

        plugins.install(cluster, {'my_plugin': cluster.inventory['plugins']['my_plugin']})

        host = cluster.nodes['all'].get_host()
        destination_data = cluster.fake_fs.read(host, '/etc/kubernetes/template.yaml')

        self.assertEqual('Compiled: {{ Yes }}', destination_data, "Inventory variable should be expanded.")


if __name__ == '__main__':
    unittest.main()
