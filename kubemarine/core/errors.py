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
import sys
import traceback

from fabric.exceptions import GroupException
from concurrent.futures import TimeoutError

KME_DICTIONARY: dict = {
    "KME0000": {
        "name": "Test exception"
    },
    "KME0003": {
        "instance": TimeoutError,
        "name": "Action took too long to complete and timed out"
    },
    "KME0004": {
        "name": "There are no workers defined in the cluster scheme"
    },
    "KME0005": {
        "name": "{hostnames} are not sudoers"
    },
    "KME0007": {
        "name": "Docker CRI can not be used with endpoints registry definition."
    },
    "KME0008": {
        "name": "Specified Kubernetes version '{version}' - cannot be used! Allowed versions are: {allowed_versions}."
    },
    "KME0009": {
        "name": "Key {key!r} is redefined for {plugin_name!r} in cluster.yaml{previous_version_spec}, "
                "but not present in procedure inventory{next_version_spec}. "
                "Please, specify required plugin configuration explicitly in procedure inventory."
    },
    "KME0010": {
        "name": "Associations are redefined for {package!r} in cluster.yaml{previous_version_spec}, "
                "but not present in procedure inventory{next_version_spec}. "
                "Please, specify required associations explicitly in procedure inventory."
    },
    "KME0011": {
        "name": "Key {key!r} is redefined for third-party {thirdparty!r} in cluster.yaml{previous_version_spec}, "
                "but not present in procedure inventory{next_version_spec}. "
                "Please, specify required third-party configuration explicitly in procedure inventory."
    },
    "KME0012": {
        "name": "Upgrade is possible only for cluster with all nodes having the same and supported OS family."
    }
}


# TODO: support for more complex KME00XX objects with custom constructors
class KME(RuntimeError):
    def __init__(self, code, **kwargs):
        self.code = code
        self.kme = KME_DICTIONARY.get(self.code)
        if self.kme is None:
            raise ValueError('An error was raised with an unknown error code')
        self.message = self.kme.get('name').format(**kwargs)
        super().__init__(self.message)

    def __str__(self):
        return self.code + ": " + self.message


class FailException(Exception):
    def __init__(self, message='', reason: Exception = None, hint=''):
        super().__init__(message)
        self.message = message
        self.reason = reason
        self.hint = hint


def pretty_print_error(reason: Exception, log=None) -> None:
    """
    Parses the passed error and nicely displays its name and structure depending on what was passed.
    The method outputs to stdout by default, but will use the logger if one is specified.
    :param reason: an exception that caused the failure.
    :param log: logger object, if you need to write a log there
    :return: None
    """

    if reason is None:
        return

    if isinstance(reason, KME):
        if log:
            log.critical(reason)
        else:
            sys.stderr.write(str(reason))

        return

    for dictionary_code, dictionary_kme in KME_DICTIONARY.items():
        if dictionary_kme.get('instance') and isinstance(reason, dictionary_kme['instance']):
            kme = KME(dictionary_code)

            if log:
                log.critical(kme)
            else:
                sys.stderr.write(str(kme))

            return

    if isinstance(reason, GroupException):
        description = "KME0002: Remote group exception"

        if log:
            log.critical(description)
        else:
            sys.stderr.write(f"{description}\n")

        for connection, result in reason.result.items():
            if log:
                log.critical("%s:" % connection.host)
            else:
                sys.stderr.write("\n%s:" % connection.host)

            found_dictionary_code = None
            for dictionary_code, dictionary_kme in KME_DICTIONARY.items():
                if dictionary_kme.get('instance') \
                        and isinstance(result, dictionary_kme['instance']):
                    found_dictionary_code = dictionary_code
                    break

            if found_dictionary_code:
                kme = KME(found_dictionary_code)
                if log:
                    log.critical("\t" + str(kme))
                else:
                    sys.stderr.write("\n\t%s\n" % str(kme))
            else:
                if log:
                    log.critical("\t" + str(result).replace("\n", "\n\t"))
                else:
                    sys.stderr.write("\n\t%s\n" % str(result).replace("\n", "\n\t"))

        return

    if log:
        log.critical('KME0001: Unexpected exception', exc_info=reason)
    else:
        sys.stderr.write("KME0001: Unexpected exception\n")
        exc_info = (type(reason), reason, reason.__traceback__)
        sio = io.StringIO()
        traceback.print_exception(*exc_info, limit=None, file=sio)
        sys.stderr.write(sio.getvalue())
