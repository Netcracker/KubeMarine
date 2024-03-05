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
