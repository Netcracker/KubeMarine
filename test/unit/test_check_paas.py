import unittest

from kubemarine import demo
from kubemarine.core import errors


class EnrichmentValidation(unittest.TestCase):
    def setUp(self):
        self.inventory = demo.generate_inventory(**demo.MINIHA)
        self.context = demo.create_silent_context(procedure='check_paas')
        self.check_paas = {
            'geo-monitor': {}
        }

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
