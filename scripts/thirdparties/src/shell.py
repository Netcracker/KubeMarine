import os
import subprocess
import sys
from typing import List
from urllib import request

SYNC_CACHE = os.path.abspath(f"{__file__}/../../.synccache")
TEMP_FILE = os.path.join(SYNC_CACHE, "tempfile")


def info(message: str):
    if os.name != 'nt':
        message = f'\033[1;32m{message}\033[0m'
    print(message)


def fatal(message: str):
    print(f'\033[1;31m{message}\033[0m')
    sys.exit(1)


def run(args: List[str]) -> str:
    print(f" > {' '.join(args)}")
    return subprocess.run(args, capture_output=True, check=True) \
        .stdout.decode('utf-8')


def curl(source: str, filepath: str):
    if os.path.exists(filepath):
        os.remove(filepath)

    request.urlretrieve(source, filepath)
