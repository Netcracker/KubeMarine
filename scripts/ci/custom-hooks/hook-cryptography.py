from typing import List, Tuple

from PyInstaller.utils.hooks import copy_metadata

datas = copy_metadata('cryptography')

# Starting from cryptography 40.0.0, PyInstaller is no longer able to build the binary for macOS arm64 platform
# being on macOS x86_64 platform due to failing _pyinstaller_hooks_contrib/hooks/stdhooks/hook-cryptography.py
# This script provides custom effectively equal implementation of the hook.

# Use the following commented out script to regenerate `binaries` and `hiddenimports`,
# being on the macOS arm64 platform, or other platform where the script is working.

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
    'cryptography.hazmat.backends.openssl.cmac',
    'cryptography.hazmat.backends.openssl.decode_asn1',
    'cryptography.hazmat.backends.openssl.ec',
    'cryptography.hazmat.backends.openssl.rsa',
    'cryptography.hazmat.backends.openssl.utils',
    'cryptography.hazmat.bindings.openssl',
    'cryptography.hazmat.bindings.openssl._conditional',
    'cryptography.hazmat.bindings.openssl.binding',
    '_cffi_backend'
]
