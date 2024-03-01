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

import fileinput
import subprocess
import sys
from typing import List
import tarfile

PIP_VERSION = "23.3.1"
PYINSTALLER_VERSION = "6.2.0"
# Pinned version is used because scripts/ci/custom-hooks/hook-cryptography.py
# relies on internal implementation of pyinstaller-hooks-contrib.
# Need to regenerate scripts/ci/custom-hooks/hook-cryptography.py each time the version is upgraded.
PYINSTALLER_HOOK_CONTRIB_VERSION = "2023.10"


def call(args: List[str]) -> None:
    return_code = subprocess.call(args)
    if return_code != 0:
        sys.exit(return_code)

# Copy ipip_check from package
with open('kubemarine/version', 'r') as version_file:
    version = version_file.readline().split('\n')[0].split('v')[1]

with tarfile.open(f"dist/kubemarine-{version}.tar.gz") as arch:
    file_obj = arch.extractfile(f"kubemarine-{version}/kubemarine/resources/scripts/ipip_check.gz")
    with open('kubemarine/resources/scripts/ipip_check.gz', 'wb') as binary:
        if file_obj is not None:
            binary.write(file_obj.read())

# Install exact version of pip, because 'scripts/ci/install_package.py' relies on its internal implementation.
# Note that downgrade is possible.
# https://github.com/pypa/pip/blob/23.3.1/docs/html/user_guide.rst#using-pip-from-your-program
call([sys.executable, '-m', 'pip', 'install', f'pip=={PIP_VERSION}'])

target_arch = None
if len(sys.argv) > 1:
    target_arch = sys.argv[1]

install_package = [sys.executable, 'scripts/ci/install_package.py']
if target_arch:
    install_package.append(target_arch)
call(install_package)

# To avoid ambiguity, remove Kubemarine package to surely run PyInstaller on sources.
call(['pip', 'uninstall', '-y', 'kubemarine'])
call(['pip', 'install', f'pyinstaller=={PYINSTALLER_VERSION}', f'pyinstaller-hooks-contrib=={PYINSTALLER_HOOK_CONTRIB_VERSION}'])

if target_arch:
    with fileinput.FileInput('kubemarine.spec', inplace=True) as file:
        for line in file:
            if "target_arch = None" == line.strip():
                line = f"target_arch = '{target_arch}'\n"
            print(line, end='')

call(['pyinstaller', 'kubemarine.spec', '--noconfirm'])
