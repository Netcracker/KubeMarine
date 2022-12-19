import unittest
from copy import deepcopy

from kubemarine import demo
from kubemarine.core import errors


class EnrichmentValidation(unittest.TestCase):
    def _inventory(self, admission):
        self.inventory = demo.generate_inventory(**demo.ALLINONE)
        self.inventory['rbac'] = {
            'admission': admission,
            admission: {
                'pod-security': 'enabled'
            }
        }
        return self.inventory['rbac'][admission]

    def _new_cluster(self):
        return demo.new_cluster(deepcopy(self.inventory))

    def test_unexpected_admission(self):
        inventory = demo.generate_inventory(**demo.ALLINONE)
        inventory['rbac'] = {
            'admission': 'unexpected'
        }
        with self.assertRaisesRegex(errors.FailException, r"Value should be one of \['psp', 'pss']"):
            demo.new_cluster(inventory)

    def test_unexpected_pod_security(self):
        for admission in ('psp', 'pss'):
            self._inventory(admission)['pod-security'] = 'unexpected'
            with self.assertRaisesRegex(errors.FailException, r"Value should be one of \['enabled', 'disabled']"):
                self._new_cluster()

    def test_pss_invalid_profile(self):
        self._inventory('pss')['defaults'] = {'enforce': 'unexpected'}
        with self.assertRaisesRegex(errors.FailException, r"Value should be one of \['privileged', 'baseline', 'restricted']"):
            self._new_cluster()

    def test_psp_unexpected_oob_policy_flag(self):
        self._inventory('psp')['oob-policies'] = {'default': 'unexpected'}
        with self.assertRaisesRegex(errors.FailException, r"Value should be one of \['enabled', 'disabled']"):
            self._new_cluster()

    def test_psp_custom_psp_list_unexpected_kind(self):
        self._inventory('psp')['custom-policies'] = {'psp-list': [self._stub_resource('Unexpected')]}
        with self.assertRaisesRegex(errors.FailException, r"Value should be one of \['PodSecurityPolicy']"):
            self._new_cluster()

    def test_psp_custom_roles_list_unexpected_kind(self):
        self._inventory('psp')['custom-policies'] = {'roles-list': [self._stub_resource('Unexpected')]}
        with self.assertRaisesRegex(errors.FailException, r"Value should be one of \['Role', 'ClusterRole']"):
            self._new_cluster()

    def test_psp_custom_bindings_list_unexpected_kind(self):
        self._inventory('psp')['custom-policies'] = {'bindings-list': [self._stub_resource('Unexpected')]}
        with self.assertRaisesRegex(errors.FailException, r"Value should be one of \['RoleBinding', 'ClusterRoleBinding']"):
            self._new_cluster()

    def _stub_resource(self, kind):
        return {
            'apiVersion': 'policy/v1beta1',
            'kind': kind,
            'metadata': {
                'name': 'custom'
            }
        }


if __name__ == '__main__':
    unittest.main()
