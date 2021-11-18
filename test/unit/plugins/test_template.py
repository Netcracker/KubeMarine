import unittest

from kubetool import demo
from kubetool.plugins import verify_template, apply_template


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
                "create_files": ["./test_templates/test_template.yaml"],
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
                # Create new fake cluster
                cluster = demo.new_cluster(
                    demo.generate_inventory(**demo.FULLHA))
                # Create new test config with the source value
                config = {
                    "source": tc["source"],
                    'apply_required': False,
                }

                if tc["valid"]:
                    # If test case is valid just run the function
                    apply_template(cluster, config)
                else:
                    # If test case is not valid check for exception raise
                    self.assertRaises(
                        Exception,
                        apply_template,
                        cluster, config
                    )
