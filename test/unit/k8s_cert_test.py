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

from kubemarine import k8s_certs


class K8sCertTest(unittest.TestCase):
    def test_single_all_verify_succeeds(self):
        self.assertTrue(k8s_certs.verify_all_is_absent_or_single(["all"]))

    def test_single_all_verify_succeeds_absent(self):
        self.assertTrue(k8s_certs.verify_all_is_absent_or_single(["absent all", "and something else"]))

    def test_single_all_verify_fails(self):
        with self.assertRaisesRegex(Exception, "Found 'all' in certs list, but it is not single"):
            k8s_certs.verify_all_is_absent_or_single(["all", "and something else"])
