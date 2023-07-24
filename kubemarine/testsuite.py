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
import textwrap
from traceback import *
import csv
from datetime import datetime
from types import TracebackType
from typing import Dict, Optional, Type, Union, List

from kubemarine.core import utils, log

from kubemarine.core.cluster import KubernetesCluster
from kubemarine.core.group import GroupException

TC_UNKNOWN = -1
TC_PASSED = 0
TC_FAILED = 1
TC_WARNED = 2
TC_EXCEPTED = 3

badges_weights = {
    'succeeded': 0,
    'warned': 1,
    'failed': 2,
    'excepted': 3,
    'unknown': 4,
}


class TestCase:

    def __enter__(self) -> 'TestCase':
        return self

    def __exit__(self, type: Optional[Type[Exception]], value: Optional[Exception],
                 traceback: Optional[TracebackType]) -> bool:
        if value is None:
            if self.status is TC_UNKNOWN:
                self.success()
        elif isinstance(value, TestFailure):
            self.fail(value)
        elif isinstance(value, TestWarn):
            self.warn(value)
        else:
            self.exception(value)
        print(self.get_summary(show_hint=True))
        return True

    def __init__(self, cluster: KubernetesCluster, id: str, category: str, name: str,
                 default_results: str = None, minimal: int = None, recommended: int = None):
        self.include_in_ts(cluster.context['testsuite'])
        self.category = category
        self.id = str(id)
        self.name = name
        self.status = TC_UNKNOWN
        self.results: Union[str, BaseException, None] = default_results
        self.minimal = minimal
        self.recommended = recommended
        self.cluster = cluster

    def include_in_ts(self, ts: 'TestSuite') -> None:
        ts.register_tc(self)

    def success(self, results: str = None) -> None:
        if self.results is None:
            self.results = results
        self.status = TC_PASSED

    def fail(self, results: BaseException) -> None:
        self.status = TC_FAILED
        self.results = results

    def warn(self, results: BaseException) -> None:
        self.status = TC_WARNED
        self.results = results

    def exception(self, results: BaseException) -> None:
        self.status = TC_EXCEPTED
        if isinstance(results, GroupException):
            self.cluster.log.debug(results)
            self.results = "Remote group exception"
        else:
            print_exc()
            self.results = results

    def get_summary(self, show_hint: bool = False, show_minimal: bool = False, show_recommended: bool = False) -> str:
        output = ""

        output += " " * (15 - len(self.category))
        output += self.category + "  "

        color = ""
        if self.is_succeeded():
            if self.check_color():
                color = "\x1b[38;5;041m"
                output += " \x1b[48;5;041m\x1b[38;5;232m   OK   \x1b[49m\x1b[39m  "
            else:
                output += "    OK     "
        if self.is_failed():
            if self.check_color():
                color = "\x1b[38;5;196m"
                output += " \x1b[48;5;196m\x1b[38;5;231m  FAIL  \x1b[49m\x1b[39m  "
            else:
                output += "   FAIL    "
        if self.is_warned():
            if self.check_color():
                color = "\x1b[38;5;208m"
                output += " \x1b[48;5;208m\x1b[38;5;231m  WARN  \x1b[49m\x1b[39m  "
            else:
                output += "   WARN    "
        if self.is_excepted():
            if self.check_color():
                color = "\x1b[31m"
                output += " \x1b[41m ERROR? \x1b[49m  "
            else:
                output += "  ERROR?   "

        output += self.id + "  "
        output += self.name + " "

        results = " " + str(self.results)

        output += "." * (146 - len(output) - len(results))
        if self.check_color():
            output += "%s%s\x1b[39m" % (color, results)
        else:
            output += "%s" % (results)

        if show_minimal:
            if self.minimal is None:
                output += ' ' * 15
            else:
                minimal = str(self.minimal)
                output += ' ' * (15-len(minimal)) + minimal

        if show_recommended:
            if self.recommended is None:
                output += ' ' * 14
            else:
                recommended = str(self.recommended)
                output += ' ' * (14-len(recommended)) + recommended

        if show_hint and (isinstance(self.results, TestFailure) or isinstance(self.results, TestWarn)) and self.results.hint is not None:
            output += "\n                  HINT:\n" + textwrap.indent(str(self.results.hint), "                       ")

        return output

    def check_color(self) -> bool:
        for handler in self.cluster.log.handlers:
            if isinstance(handler, log.StdoutHandler) and handler.formatter.colorize:
                return True
        return False

    def get_readable_status(self) -> str:
        if self.is_succeeded():
            return 'ok'
        if self.is_failed():
            return 'fail'
        if self.is_warned():
            return 'warning'
        if self.is_excepted():
            return 'exception'

        return "unknown"

    def is_succeeded(self) -> bool:
        return self.status is TC_PASSED

    def is_failed(self) -> bool:
        return self.status is TC_FAILED

    def is_warned(self) -> bool:
        return self.status is TC_WARNED

    def is_excepted(self) -> bool:
        return self.status is TC_EXCEPTED


class TestCaseNegativeResult(BaseException):

    def __init__(self, message: str, hint: str = None):
        super().__init__(message)
        self.message = message
        self.hint = hint


class TestFailure(TestCaseNegativeResult):
    pass


class TestWarn(TestCaseNegativeResult):
    pass


class TestSuite:

    def __init__(self) -> None:
        self.tcs: List[TestCase] = []

    def register_tc(self, tc: TestCase) -> None:
        self.tcs.append(tc)

    def is_any_test_failed(self) -> bool:
        for tc in self.tcs:
            if tc.is_failed() or tc.is_excepted():
                return True
        return False

    def is_any_test_warned(self) -> bool:
        for tc in self.tcs:
            if tc.is_warned():
                return True
        return False

    def get_final_summary(self, show_minimal: bool = True, show_recommended: bool = True) -> str:
        result = "          Group    Status   ID    Test                                                               Actual result"
        if show_minimal:
            result += "        Minimal"
        if show_recommended:
            result += "   Recommended"
        result += "\n"

        for tc in self.tcs:
            result += "\n" + tc.get_summary(show_minimal=show_minimal, show_recommended=show_recommended)

        result += "\n\nOVERALL RESULTS: "

        for key, value in sorted(self.get_stats_data().items(), key=lambda _key: badges_weights[_key[0]]):
            colors = ''
            if tc.check_color():
                if key == 'succeeded':
                    colors = "\x1b[48;5;041m\x1b[38;5;232m"
                if key == 'failed':
                    colors = "\x1b[48;5;196m\x1b[38;5;231m"
                if key == 'warned':
                    colors = "\x1b[48;5;208m\x1b[38;5;231m"
                if key == 'excepted':
                    colors = "\x1b[41m"
                result += "%s %s %s \x1b[49m\x1b[39m " % (colors, value ,key.upper())
            else:
                result += "%s %s  " % (value ,key.upper())

        result += "\n"

        return result

    def print_final_status(self, logger: log.EnhancedLogger) -> None:
        if self.is_any_test_failed():
            logger.error("\nTEST FAILED"
                      "\nThe environment does not meet the minimal requirements. Check the test report and resolve the issues.")
            return
        if self.is_any_test_warned():
            logger.warning("\nTEST PASSED WITH WARNINGS"
                        "\nThe environment meets the minimal requirements, but is not as recommended. Try to check the test report and resolve the issues.")
            return
        logger.info("\nTEST PASSED")

    def get_stats_data(self) -> Dict[str, int]:
        results: Dict[str, int] = {}
        for tc in self.tcs:
            key = 'unknown'
            if tc.is_succeeded():
                key = 'succeeded'
            elif tc.is_failed():
                key = 'failed'
            elif tc.is_warned():
                key = 'warned'
            elif tc.is_excepted():
                key = 'excepted'
            value = results.get(key, 0) + 1
            results[key] = value
        return results

    def save_csv(self, destination_file_path: str, delimiter: str = ';') -> None:
        stream = io.StringIO()

        csv_writer = csv.writer(stream, delimiter=delimiter, quotechar='"', quoting=csv.QUOTE_MINIMAL)
        csv_writer.writerow(['group', 'status', 'test_id', 'test_name', 'current_result', 'minimal_result', 'recommended_result'])
        for tc in self.tcs:
            csv_writer.writerow([
                tc.category.lower(),
                tc.get_readable_status(),
                tc.id,
                tc.name,
                tc.results,
                tc.minimal,
                tc.recommended
            ])

        utils.dump_file({}, stream, destination_file_path, dump_location=False)

    def save_html(self, destination_file_path: str, check_type: str, append_styles: bool = True) -> None:
        stream = io.StringIO()

        stream.write('<!DOCTYPE html><html><head><meta charset="utf-8"><title>%s Check Report</title></head><body><div id="date">%s</div><div id="stats">' % (check_type, datetime.utcnow()))
        for key, value in sorted(self.get_stats_data().items(), key=lambda _key: badges_weights[_key[0]]):
            stream.write('<div class="%s">%s %s</div>' % (key, value, key))
        stream.write('</div><h1>%s Check Report</h1><table>' % check_type)
        stream.write('<thead><tr><td>Group</td><td>Status</td><td>ID</td><td>Test</td><td>Actual Result</td><td>Minimal</td><td>Recommended</td></tr></thead><tbody>')
        for tc in self.tcs:
            minimal = ''
            if tc.minimal is not None:
                minimal = str(tc.minimal)
            recommended = ''
            if tc.recommended is not None:
                recommended = str(tc.recommended)
            stream.write('<tr class="%s"><td>%s</td><td><div>%s</div></td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>' %
                         (tc.get_readable_status(),
                          tc.category.lower(),
                          tc.get_readable_status(),
                          tc.id,
                          tc.name,
                          tc.results,
                          minimal,
                          recommended
                          ))
        stream.write('</tbody></table>')
        if append_styles:
            css = utils.read_internal('resources/reports/check_report.css')
            stream.write('<style>\n%s\n</style>' % css)

        stream.write('</body></html>')

        utils.dump_file({}, stream, destination_file_path, dump_location=False)
