# Copyright 2021-2022 NetCracker Technology Corporation
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
