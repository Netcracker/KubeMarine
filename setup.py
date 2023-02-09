import re

from setuptools import setup


def read(path):
    with open(path, 'r', encoding='utf-8') as f:
        return f.read()


VERSION = read("kubemarine/version").strip()

README = read("README.md")
# Replace all relative links (not starting with http[s]://) to absolute referring to specific version on GitHub
README = re.sub(
    r'\[(.*)]\((?!https?://)(.*)\)',
    rf'[\1](https://github.com/Netcracker/KubeMarine/blob/{VERSION}/\2)',
    README
)

# Though deprecated, it seems to be the only way to provide shell scripts.
SCRIPTS=["bin/kubemarine.cmd", "bin/kubemarine"]

setup(
    scripts=SCRIPTS,
    version=VERSION,
    long_description=README,
    long_description_content_type='text/markdown'
)
