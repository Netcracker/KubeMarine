from textwrap import dedent
import yaml
from io import StringIO

from kubemarine.core.action import Action
from kubemarine.core.patch import RegularPatch
from kubemarine.core.resources import DynamicResources
from kubemarine import kubernetes

class TheAction(Action):
    def __init__(self):
        super().__init__("Update API Server TLS cipher suites")

    def run(self, res: DynamicResources):
        cluster = res.cluster()
        kubernetes_nodes = cluster.make_group_from_roles(['control-plane'])

        for member_node in kubernetes_nodes.get_ordered_members_list():
            apiserver_file = "/etc/kubernetes/manifests/kube-apiserver.yaml"

            # Load the YAML configuration
            try:
                apiserver_config = yaml.safe_load(member_node.sudo(f"cat {apiserver_file}").get_simple_out())
            except yaml.YAMLError as exc:
                cluster.log.error(f"Failed to parse YAML file: {exc}")
                return

            # Modify the YAML structure (adjust the path as needed)
            apiserver_config['spec']['containers'][0]['command'].append("--tls-cipher-suites=TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384")

            # Dump the modified YAML back to a string
            updated_config = yaml.dump(apiserver_config)

            # Write the updated configuration to the file
            member_node.put(StringIO(updated_config), apiserver_file, backup=True, sudo=True)


class ApiServerCipherSuites(RegularPatch):
    def __init__(self):
        super().__init__("apiserver_cipher_suites")

    @property
    def action(self) -> Action:
        return TheAction()

    @property
    def description(self) -> str:
        return dedent(
            f"""\
            Patch to update the API server TLS cipher suites.
            """.rstrip()
        )