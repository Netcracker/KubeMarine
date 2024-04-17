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
import re
import unittest
from test.unit import utils as test_utils

from kubemarine import demo, cri
from kubemarine.core import errors
from kubemarine.core.cluster import KubernetesCluster


class TestContainerdCriEnrichment(unittest.TestCase):
    def do_successful_enrichment(self, inventory: dict) -> KubernetesCluster:
        try:
            return demo.new_cluster(inventory)
        except errors.FailException as e:
            self.fail(f"Can't enrich containerd configuration: {e.message}")

    def do_failed_enrichment(self, inventory: dict, expected_message: str):
        try:
            demo.new_cluster(inventory)
        except errors.FailException as e:
            self.assertEqual(expected_message, e.message)

    def test_fail_if_registry_mirrors_and_config_path_are_used(self):
        # Fail, if registry.mirror and config_path are configured
        inventory = demo.generate_inventory(**demo.ALLINONE)
        inventory['services']['cri'] = {
            'containerdConfig': {
                'plugins."io.containerd.grpc.v1.cri".registry.mirrors."some-registry:8080"': {
                    'endpoint': ['https://some-registry:8080']
                },
                'plugins."io.containerd.grpc.v1.cri".registry': {
                    'config_path': '/etc/containerd/certs.d'
                }
            }
        }
        self.do_failed_enrichment(inventory, 'Invalid containerd configuration: '
                                             'mirrors for "io.containerd.grpc.v1.cri" plugin '
                                             'in services.cri.containerdConfig can\'t be set when '
                                             'config_path for "io.containerd.grpc.v1.cri" plugin '
                                             'in services.cri.containerdConfig is provided')

    def test_fail_if_registry_configs_tls_and_config_path_are_used(self):
        # Fail, if registry.configs.tls and config_path are configured
        inventory = demo.generate_inventory(**demo.ALLINONE)
        inventory['services']['cri'] = {
            'containerdConfig': {
                'plugins."io.containerd.grpc.v1.cri".registry.configs."some-registry:8080".tls': {
                    'insecure_skip_verify': True
                },
                'plugins."io.containerd.grpc.v1.cri".registry': {
                    'config_path': '/etc/containerd/certs.d'
                }
            }
        }
        self.do_failed_enrichment(inventory, 'Invalid containerd configuration: '
                                             'configs.tls for "io.containerd.grpc.v1.cri" plugin '
                                             'in services.cri.containerdConfig can\'t be set when '
                                             'config_path for "io.containerd.grpc.v1.cri" plugin '
                                             'in services.cri.containerdConfig is provided')

    def test_fail_if_registry_mirrors_and_containerd_registries_config_are_used(self):
        # Fail, if registry.mirror and containerd registries config are configured
        inventory = demo.generate_inventory(**demo.ALLINONE)
        inventory['services']['cri'] = {
            'containerdConfig': {
                'plugins."io.containerd.grpc.v1.cri".registry.mirrors."some-registry:8080"': {
                    'endpoint': ['https://some-registry:8080']
                }
            },
            'containerdRegistriesConfig': {
                'some-registry:8080': {
                    'host."https://some-registry:8080"': {
                        'skip_verify': True
                    }
                }
            }
        }
        self.do_failed_enrichment(inventory, 'Invalid containerd configuration: '
                                             'mirrors for "io.containerd.grpc.v1.cri" plugin '
                                             'in services.cri.containerdConfig can\'t be set when '
                                             'services.cri.containerdRegistriesConfig is provided')

    def test_fail_if_registry_configs_tls_and_containerd_registries_config_are_used(self):
        # Fail, if registry.mirror and config_path are configured
        inventory = demo.generate_inventory(**demo.ALLINONE)
        inventory['services']['cri'] = {
            'containerdConfig': {
                'plugins."io.containerd.grpc.v1.cri".registry.configs."some-registry:8080".tls': {
                    'insecure_skip_verify': True
                }
            },
            'containerdRegistriesConfig': {
                'some-registry:8080': {
                    'host."https://some-registry:8080"': {
                        'skip_verify': True
                    }
                }
            }
        }
        self.do_failed_enrichment(inventory, 'Invalid containerd configuration: '
                                             'configs.tls for "io.containerd.grpc.v1.cri" plugin '
                                             'in services.cri.containerdConfig can\'t be set when '
                                             'services.cri.containerdRegistriesConfig is provided')

    def test_do_not_fail_if_only_old_format_config_is_used(self):
        # Do not fail, if only registry.mirror, registry.configs.tls or registry.config.auth are configured
        inventory = demo.generate_inventory(**demo.ALLINONE)
        inventory['services']['cri'] = {
            'containerdConfig': {
                'plugins."io.containerd.grpc.v1.cri".registry.mirrors."some-registry:8080"': {
                    'endpoint': ['https://some-registry:8080']
                },
                'plugins."io.containerd.grpc.v1.cri".registry.configs."some-registry:8080".tls': {
                    'insecure_skip_verify': True
                },
                'plugins."io.containerd.grpc.v1.cri".registry.configs."some-registry:8080".auth': {
                    'auth': 'YWRtaW46YWRtaW4='
                }
            }
        }
        self.do_successful_enrichment(inventory)

    def test_do_not_fail_if_only_new_format_config_is_used(self):
        # Do not fail, if only registry.config_path, registry.configs.auth or containerdRegistriesConfig are configured
        inventory = demo.generate_inventory(**demo.ALLINONE)
        inventory['services']['cri'] = {
            'containerdConfig': {
                'plugins."io.containerd.grpc.v1.cri".registry': {
                    'config_path': '/etc/containerd/certs.d'
                },
                'plugins."io.containerd.grpc.v1.cri".registry.configs."some-registry:8080".auth': {
                    'auth': 'YWRtaW46YWRtaW4='
                }
            },
            'containerdRegistriesConfig': {
                'some-registry:8080': {
                    'host."https://some-registry:8080"': {
                        'skip_verify': True
                    }
                }
            }
        }
        self.do_successful_enrichment(inventory)

    def test_do_not_fail_if_no_format_config_is_used(self):
        # Do not fail, if only no configuration
        inventory = demo.generate_inventory(**demo.ALLINONE)
        self.do_successful_enrichment(inventory)

    def test_config_path_enrichment_for_old_format(self):
        # Do not enrich, if old format fields are specified
        inventory = demo.generate_inventory(**demo.ALLINONE)
        inventory['services']['cri'] = {
            'containerdConfig': {
                'plugins."io.containerd.grpc.v1.cri".registry.mirrors."some-registry:8080"': {
                    'endpoint': ['https://some-registry:8080']
                }
            }
        }
        cluster = self.do_successful_enrichment(inventory)
        self.assertNotIn('config_path', cluster.inventory['services']['cri']['containerdConfig']
                         .get('plugins."io.containerd.grpc.v1.cri".registry', {}))

        inventory = demo.generate_inventory(**demo.ALLINONE)
        inventory['services']['cri'] = {
            'containerdConfig': {
                'plugins."io.containerd.grpc.v1.cri".registry.configs."some-registry:8080".tls': {
                    'insecure_skip_verify': True
                },
            }
        }
        cluster = self.do_successful_enrichment(inventory)
        self.assertNotIn('config_path', cluster.inventory['services']['cri']['containerdConfig']
                         .get('plugins."io.containerd.grpc.v1.cri".registry', {}))

    def test_config_path_enrichment_for_new_format(self):
        # Enrich by default for new format
        inventory = demo.generate_inventory(**demo.ALLINONE)
        inventory['services']['cri'] = {
            'containerdConfig': {
                'plugins."io.containerd.grpc.v1.cri".registry.configs."some-registry:8080".auth': {
                    'auth': 'YWRtaW46YWRtaW4='
                }
            },
            'containerdRegistriesConfig': {
                'some-registry:8080': {
                    'host."https://some-registry:8080"': {
                        'skip_verify': True
                    }
                }
            }
        }
        cluster = self.do_successful_enrichment(inventory)
        containerd_config = cluster.inventory['services']['cri']['containerdConfig']
        self.assertIn('config_path', containerd_config['plugins."io.containerd.grpc.v1.cri".registry'])
        self.assertEqual('/etc/containerd/certs.d',
                         containerd_config['plugins."io.containerd.grpc.v1.cri".registry']['config_path'])

    def test_config_path_enrichment_with_overriden_config_path(self):
        # Do not override user specified value
        inventory = demo.generate_inventory(**demo.ALLINONE)
        overriden_config_path = '/etc/containerd/registries'
        inventory['services']['cri'] = {
            'containerdConfig': {
                'plugins."io.containerd.grpc.v1.cri".registry': {
                    'config_path': overriden_config_path
                }
            }
        }
        cluster = self.do_successful_enrichment(inventory)
        containerd_config = cluster.inventory['services']['cri']['containerdConfig']
        self.assertIn('config_path', containerd_config['plugins."io.containerd.grpc.v1.cri".registry'])
        self.assertNotEqual('/etc/containerd/certs.d',
                            containerd_config['plugins."io.containerd.grpc.v1.cri".registry']['config_path'])
        self.assertEqual(overriden_config_path,
                         containerd_config['plugins."io.containerd.grpc.v1.cri".registry']['config_path'])

    def test_config_path_enrichment_for_empty_configuration(self):
        # Not enrich, if no containerdRegistriesConfig is not specified
        inventory = demo.generate_inventory(**demo.ALLINONE)
        cluster = self.do_successful_enrichment(inventory)
        containerd_config = cluster.inventory['services']['cri']['containerdConfig']
        self.assertNotIn('config_path', containerd_config.get('plugins."io.containerd.grpc.v1.cri".registry', {}))

    def test_containerd_remove_docker_config(self):
        inventory = demo.generate_inventory(**demo.ALLINONE)
        inventory.setdefault('services', {}).setdefault('cri', {})['containerRuntime'] = 'containerd'
        cluster = demo.new_cluster(inventory)
        self.assertNotIn('dockerConfig', cluster.inventory['services']['cri'])
        self.assertNotIn('dockerConfig', test_utils.make_finalized_inventory(cluster)['services']['cri'])

    def test_docker_remove_containerd_config(self):
        inventory = demo.generate_inventory(**demo.ALLINONE)
        inventory.setdefault('services', {}).setdefault('cri', {})['containerRuntime'] = 'docker'
        cluster = demo.new_cluster(inventory)
        self.assertNotIn('containerdConfig', cluster.inventory['services']['cri'])
        self.assertNotIn('containerdConfig', test_utils.make_finalized_inventory(cluster)['services']['cri'])

    def test_containerd_forbidden_docker_config(self):
        inventory = demo.generate_inventory(**demo.ALLINONE)
        inventory.setdefault('services', {})['cri'] = {
            'containerRuntime': 'containerd',
            'dockerConfig': {'registry-mirrors': ['http://example.registry']}
        }
        with self.assertRaisesRegex(Exception, re.escape(cri.ERROR_FORBIDDEN_CRI_SECTION.format(
                key='docker', value='dockerConfig'))):
            demo.new_cluster(inventory)

    def test_docker_forbidden_container_config(self):
        inventory = demo.generate_inventory(**demo.ALLINONE)
        inventory.setdefault('services', {})['cri'] = {
            'containerRuntime': 'docker',
            'containerdConfig': {'plugins."io.containerd.grpc.v1.cri".registry': {
                'config_path': '/changed/path'
            }}
        }
        with self.assertRaisesRegex(Exception, re.escape(cri.ERROR_FORBIDDEN_CRI_SECTION.format(
                key='containerd', value='containerdConfig'))):
            demo.new_cluster(inventory)

    def test_docker_forbidden_container_registries_config(self):
        inventory = demo.generate_inventory(**demo.ALLINONE)
        inventory.setdefault('services', {})['cri'] = {
            'containerRuntime': 'docker',
            'containerdRegistriesConfig': {'some-registry:8080': {
                'host."https://some-registry:8080"': {
                    'skip_verify': True
                }
            }}
        }
        with self.assertRaisesRegex(Exception, re.escape(cri.ERROR_FORBIDDEN_CRI_SECTION.format(
                key='containerd', value='containerdRegistriesConfig'))):
            demo.new_cluster(inventory)


if __name__ == '__main__':
    unittest.main()
