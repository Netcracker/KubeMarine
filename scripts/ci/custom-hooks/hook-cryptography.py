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

from typing import List, Tuple

from PyInstaller.utils.hooks import copy_metadata

datas = copy_metadata('cryptography')

# Starting from cryptography 40.0.0, PyInstaller is no longer able to build the binary for macOS arm64 platform
# being on macOS x86_64 platform due to failing _pyinstaller_hooks_contrib/hooks/stdhooks/hook-cryptography.py
# This script provides custom effectively equal implementation of the hook.

# Use the following commented out script to regenerate `binaries` and `hiddenimports`,
# being on the macOS arm64 platform.

# import importlib.machinery
# import os
# import _pyinstaller_hooks_contrib.hooks.stdhooks
#
# hook_filename = os.path.join(os.path.dirname(_pyinstaller_hooks_contrib.hooks.stdhooks.__file__), 'hook-cryptography.py')
# mod_loader = importlib.machinery.SourceFileLoader('hook-cryptography', hook_filename)
# mod = mod_loader.load_module()
#
# lf = '\n'
# print(f"binaries: List[Tuple[str, str]] = [{lf}{f',{lf}'.join(map(lambda b: f'    ({b[0]!r}, {b[1]!r})', mod.binaries))}{lf}]")
# print(f"hiddenimports = [{lf}{f',{lf}'.join(map(lambda i: f'    {i!r}', mod.hiddenimports))}{lf}]")

binaries: List[Tuple[str, str]] = [

]
hiddenimports = [
    'cryptography.hazmat.backends',
    'cryptography.hazmat.backends.openssl',
    'cryptography.hazmat.backends.openssl.aead',
    'cryptography.hazmat.backends.openssl.backend',
    'cryptography.hazmat.backends.openssl.ciphers',
    'cryptography.hazmat.backends.openssl.decode_asn1',
    'cryptography.hazmat.bindings.openssl',
    'cryptography.hazmat.bindings.openssl._conditional',
    'cryptography.hazmat.bindings.openssl.binding',
    '_cffi_backend'
]
