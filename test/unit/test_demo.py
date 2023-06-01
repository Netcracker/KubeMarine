#!/usr/bin/env python3
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


import io
import unittest

from kubemarine import demo, system


class TestInventoryGenerator(unittest.TestCase):

    def test_fullha_generation(self):
        inventory = demo.generate_inventory(balancer=1, master=3, worker=3)
        self.assertEqual(7, len(inventory['nodes']), msg="The received number of nodes does not match the expected")


class TestNewCluster(unittest.TestCase):

    def test_created_cluster_groups(self):
        cluster = demo.new_cluster(demo.generate_inventory(**demo.FULLHA))
        self.assertEqual(1, len(cluster.nodes['balancer'].nodes), msg="Incorrect number of balancers for a full scheme")


class TestFakeShell(unittest.TestCase):

    def setUp(self):
        self.cluster = demo.new_cluster(demo.generate_inventory(**demo.FULLHA))

    def test_run(self):
        self.cluster.fake_shell.add(demo.create_nodegroup_result(self.cluster.nodes['all'], stdout='anonymous'),
                                    'run', ['whoami'])

        results = self.cluster.nodes['all'].run('whoami')
        for conn, result in results.items():
            self.assertEqual('anonymous', result.stdout, msg="Invalid fake nodegroup result stdout")

    def test_calculate_calls(self):
        self.cluster.fake_shell.reset()
        self.cluster.fake_shell.add(demo.create_nodegroup_result(self.cluster.nodes['all'],
                                                                 code=1, stderr='sudo: kubectl: command not found'),
                                    'sudo', ['kubectl cluster-info'])
        self.cluster.fake_shell.add(demo.create_nodegroup_result(self.cluster.nodes['all'], code=-1),
                                    'sudo', [self.cluster.globals['nodes']['boot']['reboot_command']])
        self.cluster.fake_shell.add(demo.create_nodegroup_result(self.cluster.nodes['all'], stdout='example result'),
                                    'sudo', ['last reboot'], usage_limit=1)
        self.cluster.fake_shell.add(demo.create_nodegroup_result(self.cluster.nodes['all'], stdout='example result 2'),
                                    'run', ["sudo -S -p '[sudo] password: ' last reboot"], usage_limit=1)

        system.reboot_group(self.cluster.nodes['master'])

        for host in self.cluster.nodes['master'].get_hosts():
            self.assertEqual(1,
                             len(self.cluster.fake_shell.history_find(host, 'sudo', ['last reboot'])),
                             msg="Wrong number of reboots in history")
            self.assertEqual(1,
                             len(self.cluster.fake_shell.history_find(
                                 host, 'run', ["sudo -S -p '[sudo] password: ' last reboot"])),
                             msg="Wrong number of reboots in history")


class TestFakeFS(unittest.TestCase):

    def setUp(self):
        self.cluster = demo.new_cluster(demo.generate_inventory(**demo.FULLHA))

    def test_put_string(self):
        self.cluster.fake_fs.reset()

        expected_data = 'hello\nworld'
        node_hostname = list(self.cluster.nodes['master'].nodes.keys())[0]

        self.cluster.fake_fs.write(node_hostname, '/tmp/test/file.txt', expected_data)
        actual_data = self.cluster.fake_fs.read(node_hostname, '/tmp/test/file.txt')

        self.assertEqual(expected_data, actual_data, msg="Written and read data are not equal")

    def test_put_bytesio(self):
        self.cluster.fake_fs.reset()

        expected_data = io.BytesIO(b'hello\nworld')
        node_hostname = list(self.cluster.nodes['master'].nodes.keys())[0]

        self.cluster.fake_fs.write(node_hostname, '/tmp/test/file.txt', expected_data)
        actual_data = self.cluster.fake_fs.read(node_hostname, '/tmp/test/file.txt').encode('utf-8')

        self.assertEqual(expected_data.getvalue(), actual_data, msg="Written and read data are not equal")

    def test_get_nonexistent(self):
        self.cluster.fake_fs.reset()

        node_hostname = list(self.cluster.nodes['master'].nodes.keys())[0]
        actual_data = self.cluster.fake_fs.read(node_hostname, '/tmp/test/file.txt')
        self.assertIsNone(actual_data, msg="Reading did not return None in response")

    def test_write_file_to_cluster(self):
        self.cluster.fake_fs.reset()

        expected_data = 'hello\nworld'
        self.cluster.nodes['master'].put(io.StringIO(expected_data), '/tmp/test/file.txt')
        actual_data_group = self.cluster.fake_fs.read_all(self.cluster.nodes['master'].get_hosts(), '/tmp/test/file.txt')

        for host, actual_data in actual_data_group.items():
            self.assertEqual(expected_data, actual_data, msg="Written and read data are not equal for node %s" % host)


if __name__ == '__main__':
    unittest.main()
