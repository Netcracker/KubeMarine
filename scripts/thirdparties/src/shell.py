import sys


def info(message: str):
    print(f'\033[1;32m{message}\033[0m')


def fatal(message: str):
    print(f'\033[1;31m{message}\033[0m')
    sys.exit(1)
