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

import base64
import json
import os
import re
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Optional, Union, ContextManager, Iterator, List, Mapping

from kubemarine.core import errors

MASKED_VAR_MIN_SYMBOLS = 6
DEFAULT_MASK = '******'


@dataclass(frozen=True)
class MaskedVar:
    name: str

    def __repr__(self):
        return repr(_get_secret(self.name))

    def __str__(self):
        return str(_get_secret(self.name))


class Environ(Mapping[str, Union[str, MaskedVar]]):
    """
    Read-only view of os.environ that secures masked variables.
    """

    def __init__(self, masked: List[str]):
        global _environ, _masked_names
        if _environ is not None:
            raise Exception("Environ was already initialized once")

        for name in masked:
            _masked_names.add(name)

        _environ = self

    def __getitem__(self, name: str) -> Union[str, MaskedVar]:
        # check presence of the variable and throw KeyError if necessary
        value = os.environ[name]

        global _masked_names
        if name in _masked_names:
            return MaskedVar(name)

        return value

    def __len__(self) -> int:
        return len(os.environ)

    def __iter__(self) -> Iterator[str]:
        return iter(os.environ)

    __slots__ = []


def environ() -> Environ:
    global _environ
    if _environ is None:
        raise Exception("Environ was not initialized")

    return _environ


@contextmanager
def execute_unsafe() -> ContextManager[None]:
    """
    All masked variables will be expanded to the real secret if accessed within the block.
    The method is not thread safe.
    """
    global _expand_context
    _expand_context['unsafe'] = True
    try:
        yield
    finally:
        _expand_context['unsafe'] = False


@contextmanager
def expand_template(template_var: str) -> ContextManager[None]:
    """
    All masked variables will be expanded to jinja2 template accessing the provided template_var variable.
    The method is not thread safe.
    """
    global _expand_context
    _expand_context['template_var'] = template_var
    try:
        yield
    finally:
        _expand_context['template_var'] = None


def secure_single_secret(text: str) -> Union[str, MaskedVar]:
    """
    If the text contains the only secret, returns MaskedVar instance describing it.
    If the text contains not the only secret, throws ValueError.
    Otherwise, if the text does not contain secrets, returns the text unchanged.

    :param text: text to search for secrets
    :return: provided text or MaskedVar instance
    """
    # Check that masked variables are initialized and verified
    env = environ()
    global _masked_names
    # Search for any secret in the text
    for name in _masked_names:
        secret = os.environ[name]
        if secret in text:
            break
    else:
        name = None
        secret = None

    if secret is None:
        return text

    if secret != text:
        raise ValueError("Text contains not the only secret")

    return env[name]


def mask_secrets(text: str) -> str:
    """
    Mask all secrets in the text.
    """
    # Check that masked variables are initialized and verified
    environ()
    global _masked_names
    for name in _masked_names:
        secret = os.environ[name]
        text = text.replace(secret, DEFAULT_MASK)
        # Kubernetes encodes data sometimes, for example in Secrets.
        base64_secret = base64.b64encode(secret.encode('ascii')).decode('ascii')
        text = text.replace(base64_secret, DEFAULT_MASK)

    return text


class _MaskedNames:
    RFC_4648 = r'A-Za-z0-9+/=\-_'
    ILLEGAL_CHARACTERS = re.compile(rf'[^{RFC_4648}@:.~]')

    def __init__(self):
        self._masked = set()

    def add(self, name: str):
        secret = os.environ.get(name, '')
        if _MaskedNames.ILLEGAL_CHARACTERS.search(secret):
            raise errors.KME("KME0013", name=name)
        if len(secret) < MASKED_VAR_MIN_SYMBOLS:
            raise errors.KME("KME0014", name=name, num=MASKED_VAR_MIN_SYMBOLS)

        self._masked.add(self._encode_name(name))

    def __contains__(self, name: str):
        return self._encode_name(name) in self._masked

    def __iter__(self) -> Iterator[str]:
        return iter(os.environ.decodekey(name) for name in self._masked)

    def __len__(self):
        return len(self._masked)

    def _encode_name(self, name: str):
        return os.environ.encodekey(name)


def _get_secret(name: str):
    global _expand_context
    if _expand_context['unsafe']:
        return os.environ[name]

    template_var = _expand_context['template_var']
    if template_var is not None:
        return '{{ %s[%s] }}' % (template_var, json.JSONEncoder().encode(name))

    return DEFAULT_MASK


_expand_context: dict = {
    'unsafe': False,
    'template_var': None
}
_masked_names: _MaskedNames = _MaskedNames()
_environ: Optional[Environ] = None
