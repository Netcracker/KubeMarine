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

import io
from contextlib import contextmanager
from typing import Iterator

from kubemarine.core.group import NodeGroup

_custom_certs = "/etc/kubernetes/custom-certs"
_config_path = _custom_certs + "/server.conf"
_private_key_path = _custom_certs + "/key"
_certificate_path = _custom_certs + "/cert"


@contextmanager
def create_tls_secret_procedure(control_plane: NodeGroup) -> Iterator[None]:
    """
    Returns a context manager to use in `with` statement that starts the tls secret creation procedure.
    All operations with the certificate and private key files that make up the secret
    will be done in the intermediate location.

    :param control_plane: control plane node to create tls secret on
    :return: context manager to start creation procedure
    """
    control_plane.sudo(f"mkdir -p {_custom_certs}")
    try:
        yield
    finally:
        control_plane.sudo(f"rm -rf {_custom_certs}")


def put_certificate(control_plane: NodeGroup, cert: io.StringIO, key: io.StringIO) -> None:
    """
    Put certificate and private key to the intermediate location.

    The method should be used within `secrets.create_tls_secret_procedure` procedure.

    :param control_plane: control plane node to create tls secret on
    :param cert: data with certificate
    :param key: data with private key
    """
    control_plane.put(cert, _certificate_path, sudo=True)
    control_plane.put(key, _private_key_path, sudo=True)


def create_certificate(control_plane: NodeGroup, config: str, customization_flags: str) -> None:
    """
    Create new certificate and private key pair in the intermediate location.

    The method should be used within `secrets.create_tls_secret_procedure` procedure.

    :param control_plane: control plane node to create tls secret on
    :param config: configuration with x509 extensions
    :param customization_flags: flags to append to the `openssl req` command to specify properties of the certificate.
    """
    control_plane.put(io.StringIO(config), _config_path, sudo=True)
    control_plane.sudo(
        f"openssl req -x509 -nodes "
        f"-out {_certificate_path} -keyout {_private_key_path} -config {_config_path} "
        f"{customization_flags}")


def get_encoded_certificate_cmd() -> str:
    """
    :return: command that produces base64-encoded certificate.
    """
    return rf"cat {_certificate_path} | base64 | tr -d '\n'"


def verify_certificate(control_plane: NodeGroup) -> bool:
    """
    Verify custom certificate and private key pair in the intermediate location.

    The method should be used within `secrets.create_tls_secret_procedure` procedure.

    :param control_plane: control plane node to create tls secret on
    :return: `true` if the certificate is valid against the private key.
    """
    crt_md5 = control_plane.sudo(f"openssl x509 -noout -modulus -in {_certificate_path} | openssl md5").get_simple_out()
    key_md5 = control_plane.sudo(f"openssl rsa -noout -modulus -in {_private_key_path} | openssl md5").get_simple_out()
    return crt_md5 == key_md5


def renew_tls_secret(control_plane: NodeGroup, name: str, namespace: str) -> None:
    """
    Create or modify a TLS secret with the specified name and namespace.
    Use certificate and private key files from the intermediate location.

    The method should be used within `secrets.create_tls_secret_procedure` procedure.

    :param control_plane: control plane node to create tls secret on
    :param name: secret name
    :param namespace: secret namespace
    """
    control_plane.sudo(
        f"kubectl create secret tls {name} --cert {_certificate_path} --key {_private_key_path} -n {namespace} "
        f"--dry-run -o yaml | sudo kubectl apply -f -", timeout=300)
