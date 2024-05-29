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
import os
import random
import re
import socket
import unittest
import ast
from copy import deepcopy
from test.unit import utils as test_utils

import invoke

from kubemarine.core import flow, static, utils
from kubemarine.core.cluster import EnrichmentStage
from kubemarine.procedures import do
from kubemarine import demo


test_msg = "test_function_return_result"


static.GLOBALS["nodes"]["remove"]["check_active_timeout"] = 0


def test_func(cluster: demo.FakeKubernetesCluster):
    # Need to fill values in cluster context in some tests to know that function was called
    current_value = cluster.context.get("test_info", 0)
    cluster.context["test_info"] = current_value + 1

    return test_msg


tasks: dict = {
    "deploy": {
        "loadbalancer": {
            "haproxy": test_func,
            "keepalived": test_func
        },
        "accounts": test_func
    },
    "overview": test_func
}

num_tasks = 4


def replace_a_func_in_dict(test_res):
    test_res_str = str(test_res).replace(str(test_func), "'a'")
    return ast.literal_eval(test_res_str)


class FlowTest(unittest.TestCase):
    def setUp(self) -> None:
        self.light_fake_shell = demo.FakeShell()

    def test_filter_flow_1(self):
        test_tasks = "deploy.loadbalancer.haproxy"

        test_res, final_list = flow.filter_flow(tasks, test_tasks, '')
        test_res = replace_a_func_in_dict(test_res)

        expected_res = {'deploy': {'loadbalancer': {'haproxy': 'a'}}}
        self.assertEqual(expected_res, test_res, "Incorrect filtered flow.")
        self.assertEqual(["deploy.loadbalancer.haproxy"], final_list, "Incorrect filtered flow.")

    def test_filter_flow_2(self):
        test_tasks = "deploy"

        test_res, final_list = flow.filter_flow(tasks, test_tasks, '')
        test_res = replace_a_func_in_dict(test_res)

        expected_res = {'deploy': {'accounts': 'a', 'loadbalancer': {'haproxy': 'a', 'keepalived': 'a'}}}
        self.assertEqual(expected_res, test_res, "Incorrect filtered flow.")
        self.assertEqual(["deploy.loadbalancer.haproxy", "deploy.loadbalancer.keepalived", "deploy.accounts"],
                         final_list, "Incorrect filtered flow.")

    def test_filter_flow_3(self):
        test_tasks = "deploy.loadbalancer.haproxy,overview"

        test_res, final_list = flow.filter_flow(tasks, test_tasks, '')
        test_res = replace_a_func_in_dict(test_res)

        expected_res = {'deploy': {'loadbalancer': {'haproxy': 'a'}}, 'overview': 'a'}
        self.assertEqual(expected_res, test_res, "Incorrect filtered flow.")
        self.assertEqual(["deploy.loadbalancer.haproxy", "overview"],
                         final_list, "Incorrect filtered flow.")

    def test_filter_flow_excluded(self):
        test_tasks = "deploy"
        excluded_tasks = "deploy.loadbalancer"

        test_res, final_list = flow.filter_flow(tasks, test_tasks, excluded_tasks)
        test_res = replace_a_func_in_dict(test_res)

        expected_res = {'deploy': {'accounts': 'a'}}
        self.assertEqual(expected_res, test_res, "Incorrect filtered flow.")
        self.assertEqual(["deploy.accounts"], final_list, "Incorrect filtered flow.")

    def test_filter_flow_excluded_whitespaces(self):
        test_tasks = "deploy"
        excluded_tasks = "  deploy.loadbalancer  , "

        test_res, final_list = flow.filter_flow(tasks, test_tasks, excluded_tasks)
        test_res = replace_a_func_in_dict(test_res)

        expected_res = {'deploy': {'accounts': 'a'}}
        self.assertEqual(expected_res, test_res, "Incorrect filtered flow.")
        self.assertEqual(["deploy.accounts"], final_list, "Incorrect filtered flow.")

    def test_filter_flow_excluded_all_subtree(self):
        test_tasks = "deploy"
        excluded_tasks = "deploy.loadbalancer,deploy.accounts"

        test_res, final_list = flow.filter_flow(tasks, test_tasks, excluded_tasks)
        test_res = replace_a_func_in_dict(test_res)

        expected_res = {}
        self.assertEqual(expected_res, test_res, "Incorrect filtered flow.")
        self.assertEqual([], final_list, "Incorrect filtered flow.")

    def test_incorrect_task_endswith_correct(self):
        test_tasks = "my.deploy.loadbalancer.haproxy"

        with self.assertRaisesRegex(Exception, re.escape(flow.ERROR_UNRECOGNIZED_TASKS_FILTER.format(tasks=test_tasks))):
            flow.filter_flow(tasks, test_tasks, '')

    def test_incorrect_task_startswith_correct(self):
        test_tasks = "deploy.loadbalancer.haproxy.xxx"

        with self.assertRaisesRegex(Exception, re.escape(flow.ERROR_UNRECOGNIZED_TASKS_FILTER.format(tasks=test_tasks))):
            flow.filter_flow(tasks, test_tasks, '')

    def test_union_of_incorrect_tasks_is_incorrect(self):
        for test_tasks in ("my.deploy", "loadbalancer", "my.deploy,loadbalancer"):
            with self.assertRaisesRegex(Exception, flow.ERROR_UNRECOGNIZED_TASKS_FILTER.format(tasks='.*')):
                flow.filter_flow(tasks, test_tasks, '')

    def test_incorrect_group_and_task_substring_of_correct(self):
        test_tasks = "deploy.loadbalancer.h"

        with self.assertRaisesRegex(Exception, re.escape(flow.ERROR_UNRECOGNIZED_TASKS_FILTER.format(tasks=test_tasks))):
            flow.filter_flow(tasks, test_tasks, '')

    def test_exclude_not_existing_tasks(self):
        test_tasks = "deploy"

        for excluded_tasks in ("deploy.lb", "deploy.lb.haproxy", "deploy.loadbalancer.HAProxy", "deploy.loadbalancer.haproxy."):
            with self.assertRaisesRegex(Exception,
                                        re.escape(flow.ERROR_UNRECOGNIZED_TASKS_FILTER.format(tasks=excluded_tasks))):
                flow.filter_flow(tasks, test_tasks, excluded_tasks)

    def test_schedule_cumulative_point(self):
        cluster = demo.new_cluster(demo.generate_inventory(**demo.FULLHA))
        flow.init_tasks_flow(cluster)
        cluster.schedule_cumulative_point(test_func)
        points = cluster.context["scheduled_cumulative_points"]
        self.assertIn(test_func, points, "Test cumulative point was not added to cluster context")

    def test_add_task_to_proceeded_list(self):
        cluster = demo.new_cluster(demo.generate_inventory(**demo.FULLHA))
        task_path = "prepare"
        flow.init_tasks_flow(cluster)
        flow.add_task_to_proceeded_list(cluster, task_path)
        proceeded_tasks = cluster.context["proceeded_tasks"]
        self.assertIn(task_path, proceeded_tasks, "Test proceeded task was not added to cluster context")

    def test_proceed_cumulative_point(self):
        cluster = demo.new_cluster(demo.generate_inventory(**demo.FULLHA))
        method_full_name = test_func.__module__ + '.' + test_func.__qualname__
        cumulative_points = {
            test_func: ['prepare.system.modprobe']
        }
        flow.init_tasks_flow(cluster)
        cluster.schedule_cumulative_point(test_func)
        res = flow.proceed_cumulative_point(cluster, cumulative_points, "prepare.system.modprobe")
        self.assertIn(test_msg, str(res.get(method_full_name)))
        self.assertEqual(1, cluster.context.get("test_info"),
                         f"It had to be one call of test_func for {method_full_name} cumulative point")

    def test_run_flow(self):
        cluster = demo.new_cluster(demo.generate_inventory(**demo.FULLHA))
        flow.init_tasks_flow(cluster)
        final_task_names = ["deploy.loadbalancer.haproxy", "deploy.loadbalancer.keepalived",
                            "deploy.accounts", "overview"]
        flow.run_tasks_recursive(tasks, final_task_names, cluster, {}, [])

        self.assertEqual(4, cluster.context["test_info"], f"Here should be 4 calls of test_func for: {final_task_names}")

    def test_run_tasks(self):
        context = demo.create_silent_context(['--tasks', 'deploy.loadbalancer.haproxy'])
        inventory = demo.generate_inventory(**demo.FULLHA)
        resources = demo.FakeResources(context, inventory, nodes_context=demo.generate_nodes_context(inventory))
        flow.run_tasks(resources, tasks)
        self.assertEqual(1, resources.cluster_if_initialized().context["test_info"],
                         "It had to be one call of test_func for deploy.loadbalancer.haproxy action")

    def test_force_proceed_cumulative_point_task_present(self):
        context = demo.create_silent_context(['--force-cumulative-points', '--tasks', 'deploy.loadbalancer.haproxy'])
        inventory = demo.generate_inventory(**demo.FULLHA)
        cumulative_points = {
            test_func: ['deploy.loadbalancer.haproxy']
        }
        resources = demo.FakeResources(context, inventory, nodes_context=demo.generate_nodes_context(inventory))
        flow.run_tasks(resources, tasks, cumulative_points=cumulative_points)
        self.assertEqual(2, resources.cluster_if_initialized().context.get("test_info"),
                         f"Both task and cumulative points should be run")

    def test_force_proceed_cumulative_point_task_absent(self):
        context = demo.create_silent_context(['--force-cumulative-points', '--tasks', 'deploy.loadbalancer.keepalived'])
        inventory = demo.generate_inventory(**demo.FULLHA)
        cumulative_points = {
            test_func: ['deploy.loadbalancer.haproxy']
        }
        resources = demo.FakeResources(context, inventory, nodes_context=demo.generate_nodes_context(inventory))
        flow.run_tasks(resources, tasks, cumulative_points=cumulative_points)
        self.assertEqual(1, resources.cluster_if_initialized().context.get("test_info"),
                         f"Cumulative point should be skipped as task is not run")

    def test_force_proceed_cumulative_point_end_of_tasks(self):
        context = demo.create_silent_context(['--force-cumulative-points', '--tasks', 'deploy.loadbalancer.keepalived'])
        inventory = demo.generate_inventory(**demo.FULLHA)
        cumulative_points = {
            test_func: [flow.END_OF_TASKS]
        }
        resources = demo.FakeResources(context, inventory, nodes_context=demo.generate_nodes_context(inventory))
        flow.run_tasks(resources, tasks, cumulative_points=cumulative_points)
        self.assertEqual(2, resources.cluster_if_initialized().context.get("test_info"),
                         f"Cumulative point should be executed at the end of tasks")

    def test_scheduled_cumulative_point_task_absent(self):
        context = demo.create_silent_context(['--tasks', 'deploy.loadbalancer.haproxy'])
        inventory = demo.generate_inventory(**demo.FULLHA)
        cumulative_points = {
            test_func: ['overview']
        }
        tasks_copy = deepcopy(tasks)
        tasks_copy['deploy']['loadbalancer']['haproxy'] = lambda cluster: cluster.schedule_cumulative_point(test_func)
        resources = demo.FakeResources(context, inventory, nodes_context=demo.generate_nodes_context(inventory))
        flow.run_tasks(resources, tasks_copy, cumulative_points=cumulative_points)
        self.assertEqual(1, resources.cluster_if_initialized().context.get("test_info"),
                         f"Cumulative point should be executed despite the related task is not run")

    def test_scheduled_cumulative_point_end_of_tasks(self):
        context = demo.create_silent_context(['--tasks', 'deploy.loadbalancer.haproxy'])
        inventory = demo.generate_inventory(**demo.FULLHA)

        def cumulative_func(cluster: demo.FakeKubernetesCluster):
            proceeded_tasks = cluster.context["proceeded_tasks"]
            self.assertIn('deploy.loadbalancer.haproxy', proceeded_tasks,
                          f"Cumulative point should be executed at the end of tasks")
            test_func(cluster)

        cumulative_points = {
            cumulative_func: [flow.END_OF_TASKS]
        }
        tasks_copy = deepcopy(tasks)
        tasks_copy['deploy']['loadbalancer']['haproxy'] = lambda cluster: cluster.schedule_cumulative_point(cumulative_func)
        resources = demo.FakeResources(context, inventory, nodes_context=demo.generate_nodes_context(inventory))
        flow.run_tasks(resources, tasks_copy, cumulative_points=cumulative_points)
        self.assertEqual(1, resources.cluster_if_initialized().context.get("test_info"),
                         f"Cumulative point should be executed at the end of tasks")

    def test_exclude_cumulative_point_scheduled(self):
        method_full_name = test_func.__module__ + '.' + test_func.__qualname__
        context = demo.create_silent_context(['--exclude-cumulative-points-methods', method_full_name])
        inventory = demo.generate_inventory(**demo.FULLHA)
        cumulative_points = {
            test_func: ['overview']
        }
        tasks_copy = deepcopy(tasks)
        tasks_copy['deploy']['loadbalancer']['haproxy'] = lambda cluster: cluster.schedule_cumulative_point(test_func)
        resources = demo.FakeResources(context, inventory, nodes_context=demo.generate_nodes_context(inventory))
        flow.run_tasks(resources, tasks_copy, cumulative_points=cumulative_points)
        self.assertEqual(num_tasks - 1, resources.cluster_if_initialized().context.get("test_info"),
                         f"Cumulative point should be excluded and not executed")

    def test_exclude_cumulative_point_not_scheduled(self):
        method_full_name = test_func.__module__ + '.' + test_func.__qualname__
        context = demo.create_silent_context(['--exclude-cumulative-points-methods', f'{method_full_name} ,'])
        inventory = demo.generate_inventory(**demo.FULLHA)
        cumulative_points = {
            test_func: ['overview']
        }
        resources = demo.FakeResources(context, inventory, nodes_context=demo.generate_nodes_context(inventory))
        flow.run_tasks(resources, tasks, cumulative_points=cumulative_points)
        self.assertEqual(num_tasks, resources.cluster_if_initialized().context.get("test_info"),
                         f"Cumulative point should not be scheduled neither executed")

    def test_exclude_invalid_cumulative_point(self):
        method_full_name = test_func.__module__ + '.' + test_func.__qualname__
        for invalid_point in ('invalid.point', f'{method_full_name}.', test_func.__module__):
            context = demo.create_silent_context(['--exclude-cumulative-points-methods', invalid_point])
            inventory = demo.generate_inventory(**demo.FULLHA)
            cumulative_points = {
                test_func: ['overview']
            }
            tasks_copy = deepcopy(tasks)
            tasks_copy['deploy']['loadbalancer']['haproxy'] \
                = lambda cluster: cluster.schedule_cumulative_point(cluster, test_func)
            resources = demo.FakeResources(context, inventory, nodes_context=demo.generate_nodes_context(inventory))
            with self.assertRaisesRegex(
                    Exception, re.escape(flow.ERROR_UNRECOGNIZED_CUMULATIVE_POINT_EXCLUDE.format(point=invalid_point))):
                flow.run_tasks(resources, tasks_copy, cumulative_points=cumulative_points)

    def test_detect_nodes_context(self):
        inventory = demo.generate_inventory(**demo.FULLHA)
        hosts = [node["address"] for node in inventory["nodes"]]
        self._stub_detect_nodes_context(inventory, hosts, hosts)
        context = demo.create_silent_context()
        res = demo.FakeResources(context, inventory, fake_shell=self.light_fake_shell)
        # not throws any exception during cluster initialization
        flow.run_tasks(res, tasks)
        cluster = res.cluster()
        self.assertEqual(4, cluster.context["test_info"],
                         "Here should be all 4 calls of test_func")

        self.assertEqual("rhel", cluster.get_os_family())
        self.assertEqual(len(hosts), len(cluster.nodes_context))
        for node_context in cluster.nodes_context.values():
            self.assertEqual({'online': True, 'accessible': True, 'sudo': 'Root'}, node_context["access"])
            self.assertEqual({'name': 'centos', 'version': '7.6', 'family': 'rhel'}, node_context["os"])
            self.assertEqual('eth0', node_context["active_interface"])

    def test_not_sudoer_does_not_interrupt_enrichment(self):
        inventory = demo.generate_inventory(**demo.FULLHA)
        hosts = [node["address"] for node in inventory["nodes"]]
        self._stub_detect_nodes_context(inventory, hosts, [])
        context = demo.create_silent_context()
        res = demo.FakeResources(context, inventory, fake_shell=self.light_fake_shell)
        flow.run_tasks(res, tasks)
        cluster = res.cluster()
        self.assertEqual(4, cluster.context["test_info"],
                         "Here should be all 4 calls of test_func")

        self.assertEqual("rhel", cluster.get_os_family())
        for node_context in cluster.nodes_context.values():
            self.assertEqual({'online': True, 'accessible': True, 'sudo': 'No'}, node_context["access"])
            # continue to collect info
            self.assertEqual({'name': 'centos', 'version': '7.6', 'family': 'rhel'}, node_context["os"])
            self.assertEqual('eth0', node_context["active_interface"])

    def test_any_offline_node_interrupts(self):
        inventory = demo.generate_inventory(**demo.FULLHA)
        online_hosts = [node["address"] for node in inventory["nodes"]]
        offline = online_hosts.pop(random.randrange(len(online_hosts)))
        self._stub_detect_nodes_context(inventory, online_hosts, [])
        context = demo.create_silent_context()
        res = demo.FakeResources(context, inventory, fake_shell=self.light_fake_shell)

        with test_utils.assert_raises_kme(self, 'KME0006', escape=True, offline=[offline], inaccessible=[]):
            flow.run_tasks(res, tasks)

    def test_upgrade_all_nodes_inaccessible(self):
        inventory = demo.generate_inventory(**demo.MINIHA_KEEPALIVED)
        inventory['services']['kubeadm'] = {
            'kubernetesVersion': 'v1.27.8'
        }
        procedure_inventory = demo.generate_procedure_inventory('upgrade')
        procedure_inventory['upgrade_plan'] = ['v1.28.8']

        self._stub_detect_nodes_context(inventory, [], [])
        context = demo.create_silent_context(['fake_path.yaml'], procedure='upgrade')
        context['upgrade_step'] = 0
        res = demo.FakeResources(context, inventory, procedure_inventory=procedure_inventory,
                                 fake_shell=self.light_fake_shell)

        with test_utils.assert_raises_kme(self, 'KME0006', escape=True,
                                          offline=[node['address'] for node in inventory['nodes']], inaccessible=[]):
            flow.run_tasks(res, tasks)

    def test_all_nodes_offline_check_iaas(self):
        inventory = demo.generate_inventory(**demo.FULLHA_KEEPALIVED)
        self._stub_detect_nodes_context(inventory, [], [])
        context = demo.create_silent_context(procedure='check_iaas')
        res = demo.FakeResources(context, inventory, fake_shell=self.light_fake_shell)
        flow.run_tasks(res, tasks)
        cluster = res.cluster()
        self.assertEqual(4, cluster.context["test_info"],
                         "Here should be all 4 calls of test_func")

        self.assertEqual("<undefined>", cluster.get_os_family())
        for node_context in cluster.nodes_context.values():
            self.assertEqual({'online': False, 'accessible': False, 'sudo': "No"}, node_context["access"])
            self.assertEqual({'name': "<undefined>", 'version': "<undefined>", 'family': "<undefined>"}, node_context["os"])
            self.assertEqual("<undefined>", node_context["active_interface"])

    def test_any_removed_node_can_be_offline(self):
        inventory = demo.generate_inventory(**demo.FULLHA_KEEPALIVED)
        online_hosts = [node["address"] for node in inventory["nodes"]]

        i = random.randrange(len(inventory["nodes"]))
        online_hosts.pop(i)
        procedure_inventory = demo.generate_procedure_inventory('remove_node')
        procedure_inventory["nodes"] = [{"name": inventory["nodes"][i]["name"]}]

        self._stub_detect_nodes_context(inventory, online_hosts, [])
        context = demo.create_silent_context(['fake_path.yaml'], procedure='remove_node')
        res = demo.FakeResources(context, inventory, procedure_inventory=procedure_inventory,
                                 fake_shell=self.light_fake_shell)

        # no exception should occur
        flow.run_tasks(res, tasks)

    def test_remove_node_if_worker_offline(self):
        inventory = demo.generate_inventory(**demo.FULLHA_KEEPALIVED)
        online_hosts = [node["address"] for node in inventory["nodes"]]
        workers = [i for i, node in enumerate(inventory["nodes"]) if 'worker' in node['roles']]

        i = random.randrange(len(workers))
        online_hosts.pop(workers[i])

        j = random.randrange(len(workers))
        while j == i:
            j = random.randrange(len(workers))

        procedure_inventory = demo.generate_procedure_inventory('remove_node')
        procedure_inventory["nodes"] = [{"name": inventory["nodes"][workers[j]]["name"]}]

        self._stub_detect_nodes_context(inventory, online_hosts, [])
        context = demo.create_silent_context(['fake_path.yaml'], procedure='remove_node')
        res = demo.FakeResources(context, inventory, procedure_inventory=procedure_inventory,
                                 fake_shell=self.light_fake_shell)

        # no exception should occur
        flow.run_tasks(res, tasks)

    def test_add_node_if_worker_offline(self):
        inventory = demo.generate_inventory(**demo.FULLHA_KEEPALIVED)
        online_hosts = [node["address"] for node in inventory["nodes"]]
        workers = [i for i, node in enumerate(inventory["nodes"]) if 'worker' in node['roles']]

        i = random.randrange(len(workers))
        online_hosts.pop(workers[i])

        j = random.randrange(len(workers))
        while j == i:
            j = random.randrange(len(workers))

        self._stub_detect_nodes_context(inventory, online_hosts, [])

        added_node = inventory['nodes'].pop(workers[j])
        procedure_inventory = demo.generate_procedure_inventory('add_node')
        procedure_inventory['nodes'] = [added_node]

        context = demo.create_silent_context(['fake_path.yaml'], procedure='add_node')
        res = demo.FakeResources(context, inventory, procedure_inventory=procedure_inventory,
                                 fake_shell=self.light_fake_shell)

        # no exception should occur
        flow.run_tasks(res, tasks)

    def test_detect_nodes_context_removed_node_online(self):
        inventory = demo.generate_inventory(**demo.FULLHA_KEEPALIVED)
        hosts = [node["address"] for node in inventory["nodes"]]
        self._stub_detect_nodes_context(inventory, hosts, hosts)

        i = random.randrange(len(inventory["nodes"]))
        procedure_inventory = demo.generate_procedure_inventory('remove_node')
        procedure_inventory["nodes"] = [{"name": inventory["nodes"][i]["name"]}]

        context = demo.create_silent_context(['fake_path.yaml'], procedure='remove_node')
        res = demo.FakeResources(context, inventory, procedure_inventory=procedure_inventory,
                                 fake_shell=self.light_fake_shell)

        flow.run_tasks(res, tasks)
        cluster = res.cluster()
        self.assertEqual(4, cluster.context["test_info"],
                         "Here should be all 4 calls of test_func")

        self.assertEqual("rhel", cluster.get_os_family())
        self.assertEqual(len(hosts), len(cluster.nodes_context))
        for node_context in cluster.nodes_context.values():
            self.assertEqual({'online': True, 'accessible': True, 'sudo': 'Root'}, node_context["access"])
            self.assertEqual({'name': 'centos', 'version': '7.6', 'family': 'rhel'}, node_context["os"])
            self.assertEqual('eth0', node_context["active_interface"])

    def test_detect_nodes_context_do_procedure(self):
        inventory = {
            'nodes': [{'roles': ['master'], 'internal_address': '1.1.1.1', 'address': '1.1.1.1', 'keyfile': '/dev/null'}]
        }
        hosts = ['1.1.1.1']
        self._stub_detect_nodes_context(inventory, hosts, hosts)

        results = demo.create_hosts_result(hosts, stdout='root\n', hide=False)
        self.light_fake_shell.add(results, 'sudo', ['whoami'])

        context = do.create_context(['--', 'whoami'])
        res = demo.FakeResources(context, inventory, fake_shell=self.light_fake_shell)

        flow.ActionsFlow([do.CLIAction(context)]).run_flow(res, print_summary=False)

        cluster = res.cluster(EnrichmentStage.LIGHT)
        self.assertEqual("rhel", cluster.get_os_family())
        self.assertEqual(1, len(cluster.nodes_context))
        for node_context in cluster.nodes_context.values():
            self.assertEqual({'online': True, 'accessible': True, 'sudo': 'Root'}, node_context["access"])
            self.assertEqual({'name': 'centos', 'version': '7.6', 'family': 'rhel'}, node_context["os"])
            self.assertEqual('eth0', node_context["active_interface"])

    def test_do_master_offline(self):
        inventory = {
            'nodes': [{'roles': ['master'], 'internal_address': '1.1.1.1', 'address': '1.1.1.1', 'keyfile': '/dev/null'}]
        }
        self._stub_detect_nodes_context(inventory, [], [])

        context = do.create_context(['--', 'whoami'])
        res = demo.FakeResources(context, inventory, fake_shell=self.light_fake_shell)

        with test_utils.assert_raises_kme(self, 'KME0006', escape=True,
                                          offline=['1.1.1.1'], inaccessible=[]):
            res.cluster(EnrichmentStage.LIGHT)

    def test_kubernetes_version_not_allowed(self):
        k8s_versions = list(sorted(static.KUBERNETES_VERSIONS["compatibility_map"], key=utils.version_key))
        k8s_latest = k8s_versions[-1]
        not_allowed_version = test_utils.increment_version(k8s_latest)

        inventory = demo.generate_inventory(**demo.ALLINONE)
        inventory['services'].setdefault('kubeadm', {})['kubernetesVersion'] = not_allowed_version

        hosts = [node["address"] for node in inventory["nodes"]]
        self._stub_detect_nodes_context(inventory, hosts, hosts)
        context = demo.create_silent_context()
        res = demo.FakeResources(context, inventory, fake_shell=self.light_fake_shell)

        with test_utils.assert_raises_kme(self, "KME0008",
                                          version=re.escape(not_allowed_version),
                                          allowed_versions='.*'):
            flow.run_tasks(res, tasks)

    def _stub_detect_nodes_context(self, inventory: dict, online_nodes: list, sudoer_nodes: list):
        hosts = [node["address"] for node in inventory["nodes"]]

        self._stub_result(hosts, sudoer_nodes, online_nodes, "run", ["sudo -S -p '[sudo] password: ' last reboot"],
                          'some reboot info')
        self._stub_result(hosts, sudoer_nodes, online_nodes, "sudo", ['whoami'], 'root')

        for node in inventory["nodes"]:
            self._stub_result([node["address"]], sudoer_nodes, online_nodes, "run",
                              ["/usr/sbin/ip -o a | grep %s | awk '{print $2}'" % node["internal_address"]], 'eth0')

        with open(os.path.dirname(__file__) + "/../../resources/fetch_os_versions_example.txt", encoding='utf-8') as f:
            fetch_os_versions = f.read()

        self._stub_result(hosts, sudoer_nodes, online_nodes, "run",
                          ["cat /etc/*elease; "
                           "cat /etc/debian_version 2> /dev/null | sed 's/\\(.\\+\\)/DEBIAN_VERSION=\"\\1\"/' || true"],
                          fetch_os_versions)

    def _stub_result(self, hosts, sudoer_hosts, online_hosts, do_type, command, stdout):
        results = {}
        for host in hosts:
            if host not in online_hosts:
                results[host] = socket.timeout()
            elif host not in sudoer_hosts and do_type == 'sudo':
                results[host] = invoke.AuthFailure(None, None)
            elif host not in sudoer_hosts and 'last reboot' in command[0]:
                results[host] = invoke.Failure(None, invoke.exceptions.ResponseNotAccepted())
            else:
                results[host] = demo.create_result(stdout=stdout)
        self.light_fake_shell.add(results, do_type, command, usage_limit=1)


if __name__ == '__main__':
    unittest.main()
