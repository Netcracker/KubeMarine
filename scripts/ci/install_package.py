# Copyright 2021-2023 NetCracker Technology Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# The script installs Kubemarine package from dist/*.whl with its dependencies.
# The 1st optional argv parameter define macOS target architecture.

import glob
import sys
from importlib.metadata import version
from typing import Tuple

# pylint: disable=bad-builtin,wrong-import-position

expected_pip_version = '24.0'
pip_version = version('pip')
assert pip_version == expected_pip_version,\
    f"The script relies on internal implementation of pip and was tested on pip=={expected_pip_version}. " \
    f"To support pip=={pip_version}, the script should be manually adopted."


from pip._internal.cli.main import main as pip_main


def patch_mac_ver(mac_arch: str) -> None:
    """
    Patch platform.mac_ver() to return the target (in general, non-native) macOS architecture.
    Pip will choose wheels suitable for the target architecture when installing the packages.

    See pip._internal.models.target_python.TargetPython.get_tags() and downstream methods.

    For non-native target architecture such packages will obviously not work,
    and can only be used to be included in Kubemarine executable using PyInstaller.

    :param mac_arch: Target macOS architecture
    """
    import platform

    assert platform.system() == 'Darwin', "Target architecture is allowed only on macOS platform"
    assert mac_arch in ('x86_64', 'arm64'), f"Unexpected target architecture {mac_arch!r}"

    mac_ver_orig = platform.mac_ver

    def mac_ver(release: str = '', versioninfo: Tuple[str, str, str] = ('', '', ''), machine: str = '') \
            -> Tuple[str, Tuple[str, str, str], str]:
        result = mac_ver_orig(release, versioninfo, machine)
        return result[0], result[1], mac_arch

    platform.mac_ver = mac_ver


mac_arch = None
if len(sys.argv) > 1:
    mac_arch = sys.argv[1]


pip_args = ['install']
if mac_arch:
    patch_mac_ver(mac_arch)
    # Target architecture can be non-native.
    # We should not allow building of packages from sources, thus force pip use wheels.
    pip_args.extend(['--only-binary', ':all:'])

pip_args.append(glob.glob('dist/*.whl')[0])

sys.exit(pip_main(pip_args))
