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


import unittest

from paramiko import SSHException

from kubemarine import demo

from kubemarine.core import static
from kubemarine.core.group import CollectorCallback

ETCD_LEADER_CHANGED_MESSAGE = 'Error from server: rpc error: code = Unavailable desc = etcdserver: leader changed'

# to increase test speed, let's override global workaround timeout value
static.GLOBALS['workaround']['delay_period'] = 0


class TestUnexpectedErrors(unittest.TestCase):

    def test_etcd_leader_changed_workaround(self):
        cluster = demo.new_cluster(demo.generate_inventory(**demo.FULLHA))

        command = ['kubectl describe nodes']

        bad_results = demo.create_nodegroup_result(cluster.nodes['control-plane'], code=-1, stderr=ETCD_LEADER_CHANGED_MESSAGE)
        good_results = demo.create_nodegroup_result(cluster.nodes['control-plane'],
                                                    stdout='Kubernetes control plane is running at %s'
                                                           % cluster.inventory['cluster_name'])

        cluster.fake_shell.add(bad_results, 'sudo', command, usage_limit=1)
        cluster.fake_shell.add(good_results, 'sudo', command)

        results = cluster.nodes['control-plane'].get_any_member().sudo('kubectl describe nodes')

        for result in results.values():
            self.assertIn('is running', result.stdout, msg="After an unsuccessful attempt, the workaround mechanism "
                                                           "should have worked and got the right result, but it seems "
                                                           "something went wrong")

    def test_etcd_leader_changed_workaround_executor(self):
        cluster = demo.new_cluster(demo.generate_inventory(**demo.FULLHA))
        group = cluster.nodes["control-plane"].new_defer()

        results = demo.create_hosts_result(group.get_hosts(), stdout='foo\n')
        cluster.fake_shell.add(results, 'sudo', ['echo "foo"'])

        command = 'kubectl describe nodes'
        good_result = 'Kubernetes control plane is running at %s' % cluster.inventory['cluster_name']
        results = demo.create_hosts_result(group.get_first_member().get_hosts(),
                                           code=-1, stderr=ETCD_LEADER_CHANGED_MESSAGE)
        cluster.fake_shell.add(results, 'sudo', [command], usage_limit=1)
        results = demo.create_hosts_result(group.get_hosts(), stdout=good_result)
        cluster.fake_shell.add(results, 'sudo', [command])

        results = demo.create_hosts_result(group.get_hosts(), stdout='bar\n')
        cluster.fake_shell.add(results, 'sudo', ['echo "bar"'])

        collector = CollectorCallback(cluster)
        group.sudo('echo "foo"')
        group.sudo(command, callback=collector)
        group.sudo('echo "bar"')
        group.flush()

        for result in collector.result.values():
            self.assertEqual(good_result, result.stdout,
                             msg="After an unsuccessful attempt, the workaround mechanism "
                                 "should have worked and got the right result, but it seems "
                                 "something went wrong")

        executor_results = group.executor.get_last_results()
        self.assertEqual(3, len(executor_results))
        for tokenized_results in executor_results.values():
            self.assertEqual(3, len(tokenized_results))
            self.assertEqual(["foo\n", good_result, 'bar\n'],
                             [result.stdout for result in tokenized_results.values()])

    def test_encountered_rsa_key(self):
        cluster = demo.new_cluster(demo.generate_inventory(**demo.FULLHA))

        command = ['kubectl describe nodes']

        bad_results = demo.create_exception_result(cluster.nodes['control-plane'],
                                                   exception=SSHException('encountered RSA key, expected OPENSSH key'))
        good_results = demo.create_nodegroup_result(cluster.nodes['control-plane'],
                                                    stdout='Kubernetes control plane is running at %s'
                                                           % cluster.inventory['cluster_name'])

        cluster.fake_shell.add(bad_results, 'sudo', command, usage_limit=1)
        cluster.fake_shell.add(good_results, 'sudo', command)
        cluster.fake_shell.add(demo.create_nodegroup_result(cluster.nodes['all'], stdout='example result'),
                               'run', ["sudo -S -p '[sudo] password: ' last reboot"])

        results = cluster.nodes['control-plane'].get_any_member().sudo('kubectl describe nodes')

        for result in results.values():
            self.assertIn('is running', result.stdout, msg="After an unsuccessful attempt, the workaround mechanism "
                                                           "should have worked and got the right result, but it seems "
                                                           "something went wrong")

    def test_encountered_rsa_key_executor(self):
        cluster = demo.new_cluster(demo.generate_inventory(**demo.FULLHA))
        group = cluster.nodes["control-plane"].new_defer()

        command = 'kubectl describe nodes'
        good_result = 'Kubernetes control plane is running at %s' % cluster.inventory['cluster_name']
        results = demo.create_hosts_exception_result(group.get_first_member().get_hosts(),
                                                     exception=SSHException('encountered RSA key, expected OPENSSH key'))
        cluster.fake_shell.add(results, 'sudo', [command], usage_limit=1)
        results = demo.create_hosts_result(group.get_hosts(), stdout=good_result)
        cluster.fake_shell.add(results, 'sudo', [command])

        results = demo.create_hosts_result(group.get_hosts(), stdout='bar\n')
        cluster.fake_shell.add(results, 'sudo', ['echo "bar"'])

        cluster.fake_shell.add(demo.create_nodegroup_result(group, stdout='example result'),
                               'run', ["sudo -S -p '[sudo] password: ' last reboot"])

        collector = CollectorCallback(cluster)
        group.sudo(command, callback=collector)
        group.sudo('echo "bar"')
        group.flush()

        for result in collector.result.values():
            self.assertEqual(good_result, result.stdout,
                             msg="After an unsuccessful attempt, the workaround mechanism "
                                 "should have worked and got the right result, but it seems "
                                 "something went wrong")

        executor_results = group.executor.get_last_results()
        self.assertEqual(3, len(executor_results))
        for tokenized_results in executor_results.values():
            self.assertEqual(2, len(tokenized_results))
            self.assertEqual([good_result, 'bar\n'],
                             [result.stdout for result in tokenized_results.values()])


if __name__ == '__main__':
    unittest.main()
