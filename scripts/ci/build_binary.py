import fileinput
import subprocess
import sys


PYINSTALLER_VERSION = "5.8.0"


def call(args):
    return_code = subprocess.call(args)
    if return_code != 0:
        exit(return_code)


# Install exact version of pip, because 'scripts/ci/install_package.py' relies on its internal implementation.
# Note that downgrade is possible.
# https://github.com/pypa/pip/blob/23.0/docs/html/user_guide.rst#using-pip-from-your-program
call([sys.executable, '-m', 'pip', 'install', 'pip==23.0'])

target_arch = None
if len(sys.argv) > 1:
    target_arch = sys.argv[1]

install_package = [sys.executable, 'scripts/ci/install_package.py']
if target_arch:
    install_package.append(target_arch)
call(install_package)

# To avoid ambiguity, remove Kubemarine package to surely run PyInstaller on sources.
call(['pip', 'uninstall', '-y', 'kubemarine'])
call(['pip', 'install', f'pyinstaller=={PYINSTALLER_VERSION}'])

if target_arch:
    with fileinput.FileInput('kubemarine.spec', inplace=True) as file:
        for line in file:
            if "target_arch = None" == line.strip():
                line = f"target_arch = '{target_arch}'\n"
            print(line, end='')

call(['pyinstaller', 'kubemarine.spec', '--noconfirm'])
