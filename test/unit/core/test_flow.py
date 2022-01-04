#!/usr/bin/env python3
# Copyright 2021 NetCracker Technology Corporation
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
import ast
from unittest import mock

from kubemarine.core import flow
from kubemarine import demo

test_msg = "test_function_return_result"


def test_func(cluster):
    try:
        # Need to fill values in cluster context in some tests to know that function was called
        current_value = cluster.context.get("test_info")
        if current_value is None:
            cluster.context["test_info"] = 1
        else:
            cluster.context["test_info"] = current_value + 1
    except Exception as ex:
        print(ex)
    return test_msg


tasks = {
    "deploy": {
        "loadbalancer": {
            "haproxy": test_func,
            "keepalived": test_func
        },
        "accounts": test_func
    },
    "overview": test_func
}


def replace_a_func_in_dict(test_res):
    test_res_str = str(test_res).replace(str(test_func), "'a'")
    return ast.literal_eval(test_res_str)


class FlowTest(unittest.TestCase):
    def test_filter_flow_1(self):
        test_tasks = ["deploy.loadbalancer.haproxy"]

        test_res, final_list = flow.filter_flow(tasks, test_tasks, "")
        test_res = replace_a_func_in_dict(test_res)

        expected_res = {'deploy': {'loadbalancer': {'haproxy': 'a'}}}
        self.assertEqual(expected_res, test_res, "Incorrect filtered flow.")

    def test_filter_flow_2(self):
        test_tasks = ["deploy"]

        test_res, final_list = flow.filter_flow(tasks, test_tasks, "")
        test_res = replace_a_func_in_dict(test_res)

        expected_res = {'deploy': {'accounts': 'a', 'loadbalancer': {'haproxy': 'a', 'keepalived': 'a'}}}
        self.assertEqual(expected_res, test_res, "Incorrect filtered flow.")

    def test_filter_flow_3(self):
        test_tasks = ["deploy.loadbalancer.haproxy", "overview"]

        test_res, final_list = flow.filter_flow(tasks, test_tasks, "")
        test_res = replace_a_func_in_dict(test_res)

        expected_res = {'deploy': {'loadbalancer': {'haproxy': 'a'}}, 'overview': 'a'}
        self.assertEqual(expected_res, test_res, "Incorrect filtered flow.")

    def test_filter_flow_excluded(self):
        test_tasks = ["deploy"]
        excluded_tasks = ["deploy.loadbalancer"]

        test_res, final_list = flow.filter_flow(tasks, test_tasks, excluded_tasks)
        test_res = replace_a_func_in_dict(test_res)

        expected_res = {'deploy': {'accounts': 'a'}}
        self.assertEqual(expected_res, test_res, "Incorrect filtered flow.")

    def test_schedule_cumulative_point(self):
        cluster = demo.new_cluster(demo.generate_inventory(**demo.FULLHA))
        flow.schedule_cumulative_point(cluster, test_func)
        points = cluster.context["scheduled_cumulative_points"]
        self.assertIn(test_func, points, "Test cumulative point was not added to cluster context")

    def test_add_task_to_proceeded_list(self):
        cluster = demo.new_cluster(demo.generate_inventory(**demo.FULLHA))
        task_path = "prepare"
        flow.add_task_to_proceeded_list(cluster, task_path)
        proceeded_tasks = cluster.context["proceeded_tasks"]
        self.assertIn(task_path, proceeded_tasks, "Test proceeded task was not added to cluster context")

    def test_proceed_cumulative_point(self):
        cluster = demo.new_cluster(demo.generate_inventory(**demo.FULLHA))
        method_full_name = test_func.__module__ + '.' + test_func.__qualname__
        cumulative_points = {
            method_full_name: ['prepare.system.modprobe']
        }
        flow.schedule_cumulative_point(cluster, test_func)
        res = flow.proceed_cumulative_point(cluster, cumulative_points, "prepare.system.modprobe")
        self.assertIn(test_msg, str(res.get(method_full_name)))

    def test_run_flow(self):
        cluster = demo.new_cluster(demo.generate_inventory(**demo.FULLHA))
        flow.run_flow(tasks, cluster, {})

        self.assertEqual(4, cluster.context["test_info"], "Here should be 4 calls of test_func for: \
         deploy.loadbalancer.haproxy, deploy.loadbalancer.keepalived, deploy.accounts, overview.")

    @mock.patch('kubemarine.core.flow.load_inventory', return_value=demo.new_cluster(demo.generate_inventory(**demo.FULLHA)))
    def test_run(self, patched_func):
        test_tasks = ["deploy.loadbalancer.haproxy"]
        args = flow.new_parser("Help text").parse_args(['-v'])
        flow.run(tasks, test_tasks, [], {}, flow.create_context(args))
        cluster = patched_func.return_value
        self.assertEqual(1, cluster.context["test_info"],
                         "It had to be one call of test_func for deploy.loadbalancer.haproxy action")


if __name__ == '__main__':
    unittest.main()
