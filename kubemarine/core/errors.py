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
from abc import ABC, abstractmethod

from textwrap import dedent
from typing import Type, List

from kubemarine.core import log as klog


class GroupException(Exception):
    pass


def get_kme_dictionary() -> dict:
    return {
        "KME0000": {
            "name": "Test exception"
        },
        "KME0001": {
            "instance": KeyboardInterrupt,
            "name": "Interrupted{reason}"
        },
        "KME0002": {
            "instance": GroupException,
            "name": "Remote group exception\n{reason}"
        },
        "KME0004": {
            "name": "There are no control planes defined in the cluster scheme"
        },
        "KME0005": {
            "name": "{hostnames} are not sudoers"
        },
        "KME0006": {
            "offline": dedent(
                """\
                Nodes {offline} are not reachable.
                Check that the nodes addresses are entered correctly in the inventory.
                The nodes may also be turned off, SSH port is probably not opened or incorrect,
                or something is incorrect with the SSH daemon.
                """.rstrip()
            ),
            "inaccessible": dedent(
                """\
                Nodes {inaccessible} are not accessible through SSH.
                Check that the SSH credentials (keyfile, username, password) are entered correctly in the inventory.
                """.rstrip()
            )
        },
        "KME0008": {
            "name": "Specified Kubernetes version '{version}' - cannot be used! "
                    "Allowed versions are: {allowed_versions}."
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
            "name": "Procedure {procedure!r} is possible only for cluster "
                    "with all nodes having the same and supported OS family."
        },
        'KME0013': {
            "name": "Key 'plugins.\"io.containerd.grpc.v1.cri\".sandbox_image' is redefined for 'containerdConfig' "
                    "in cluster.yaml{previous_version_spec}, "
                    "but not present in procedure inventory{next_version_spec}. "
                    "Please, specify required 'sandbox_image' explicitly in procedure inventory."
        }
    }


class BaseKME(RuntimeError, ABC):
    def __init__(self, code: str):
        self.code = code
        if self.code not in get_kme_dictionary():
            raise ValueError('An error was raised with an unknown error code')
        self.kme: dict = get_kme_dictionary()[self.code]
        self.message = self._format()
        super().__init__(self.message)

    @abstractmethod
    def _format(self) -> str: ...

    def __str__(self) -> str:
        return self.code + ": " + self.message


class KME(BaseKME):
    def __init__(self, code: str, **kwargs: object):
        self.kwargs = kwargs
        super().__init__(code)

    def _format(self) -> str:
        if 'name' not in self.kme:
            raise ValueError('An error was raised with an unsupported error code')

        name: str = self.kme['name']
        return name.format_map(self.kwargs)


class KME0006(BaseKME):
    def __init__(self, offline: List[str], inaccessible: List[str]):
        self.offline = offline
        self.inaccessible = inaccessible
        self.summary = ""
        self.details = ""
        super().__init__("KME0006")

    def _format(self) -> str:
        self.summary = f"Failed to connect to {len(self.offline + self.inaccessible)} nodes."
        msgs = []
        if self.offline:
            msgs.append(self.kme['offline'].format(offline=self.offline))
        if self.inaccessible:
            msgs.append(self.kme['inaccessible'].format(inaccessible=self.inaccessible))
        self.details = '\n'.join(msgs)
        return self.summary + '\n' + self.details


class FailException(Exception):
    def __init__(self, message: str = '', reason: BaseException = None, hint: str = '') -> None:
        super().__init__(message)
        self.message = message
        self.reason = reason
        self.hint = hint


def wrap_kme_exception(reason: BaseException) -> BaseException:
    for dictionary_code, dictionary_kme in get_kme_dictionary().items():
        exception_class: Type[BaseException] = dictionary_kme.get('instance')
        if exception_class is not None and isinstance(reason, exception_class):
            return KME(dictionary_code, reason=reason)

    return reason


def pretty_print_error(message: str = '', reason: BaseException = None, log: klog.EnhancedLogger = None) -> None:
    """
    Parses the passed error and nicely displays its name and structure depending on what was passed.
    The method outputs to stdout by default, but will use the logger if one is specified.

    :param message: an optional message describing context of the error
    :param reason: an exception that caused the failure.
    :param log: logger object, if you need to write a log there
    :return: None
    """
    def error_logger(msg: object) -> None:
        if log:
            log.critical(msg)
        else:
            sys.stderr.write(str(msg) + "\n")

    error_logger('FAILURE!')
    if message != '':
        error_logger(message)

    if reason is None:
        return

    reason = wrap_kme_exception(reason)

    if isinstance(reason, BaseKME):
        error_logger(reason)
        return

    if log:
        log.critical('KME0001: Unexpected exception', exc_info=reason)
    else:
        sys.stderr.write("KME0001: Unexpected exception\n")
        exc_info = (type(reason), reason, reason.__traceback__)
        sio = io.StringIO()
        traceback.print_exception(*exc_info, limit=None, file=sio)
        sys.stderr.write(sio.getvalue())
