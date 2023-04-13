import subprocess
import sys
from typing import List


def info(message: str):
    print(f'\033[1;32m{message}\033[0m')


def fatal(message: str):
    print(f'\033[1;31m{message}\033[0m')
    sys.exit(1)


def run(args: List[str]) -> str:
    print(f" > {' '.join(args)}")
    return subprocess.run(args, capture_output=True, check=True)\
        .stdout.decode('utf-8')
