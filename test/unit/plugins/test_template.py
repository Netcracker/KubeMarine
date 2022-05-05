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
from kubemarine.plugins import verify_template, apply_template


class TestTemplate(unittest.TestCase):

    def test_verify_template(self):
        test_cases = [
            {
                "name": "One yaml template",
                "source": "../test/unit/plugins/test_templates/test_template1.yaml",
                "valid": True,
            },
            {
                "name": "Wildcard path matching three yaml templates",
                "source": "../test/unit/plugins/test_templates/*.yaml",
                "valid": True,
            },
            {
                "name": "Directory wildcard path matching two yaml templates",
                "source": "../test/unit/plugins/test_templates/*",
                "valid": True,
            },
            {
                "name": "Wildcard path matching zero templates",
                "source": "../test/unit/plugins/test_templates/*.conf",
                "valid": False,
            },
            {
                "name": "Path to non-existent template",
                "source": "../test/unit/plugins/test_templates/template.conf",
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
                "source": "../test/unit/plugins/test_templates/test_template1.yaml",
                "valid": True,
            },
            {
                "name": "Wildcard path matching three yaml templates",
                "apply_files": ["test_template1.yaml", "test_template2.yaml", "test_template3.yaml"],
                "source": "../test/unit/plugins/test_templates/*.yaml",
                "valid": True,
            },
            {
                "name": "Directory wildcard path matching three yaml templates",
                "apply_files": ["test_template1.yaml", "test_template2.yaml", "test_template3.yaml"],
                "source": "../test/unit/plugins/test_templates/*",
                "valid": True,
            },
            {
                "name": "Wildcard path matching zero templates",
                "source": "../test/unit/plugins/test_templates/*.conf",
                "valid": False,
            },
            {
                "name": "Path to non-existent template",
                "source": "../test/unit/plugins/test_templates/template.conf",
                "valid": False,
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

                if tc["valid"]:
                    for file in tc["apply_files"]:
                        result = demo.create_nodegroup_result(cluster.nodes["master"])
                        cluster.fake_shell.add(result, "sudo", [f"kubectl apply -f /etc/kubernetes/{file}"], usage_limit=1)

                    # If test case is valid just run the function
                    apply_template(cluster, config)

                    for file in tc["apply_files"]:
                        cnt = 0
                        for host in cluster.nodes['master'].get_hosts():
                            history = cluster.fake_shell.history_find(host, "sudo", [f"kubectl apply -f /etc/kubernetes/{file}"])
                            if len(history) == 1 and history[0]["used_times"] == 1:
                                cnt += 1
                        self.assertEqual(1, cnt)
                else:
                    # If test case is not valid check for exception raise
                    self.assertRaises(
                        ValueError,
                        apply_template,
                        cluster, config
                    )
