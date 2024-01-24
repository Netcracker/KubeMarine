
import yaml
import time
from io import StringIO
from typing import Any, Dict, List
from textwrap import dedent
from kubemarine.core.action import Action
from kubemarine.core.patch import RegularPatch
from kubemarine.core.resources import DynamicResources

class TheAction(Action):
    def __init__(self) -> None:
        super().__init__("Update API Server TLS cipher suites (if necessary)")

    def run(self, res: DynamicResources) -> None:
        cluster = res.cluster()

        # Access the raw inventory directly
        raw_inventory = res.raw_inventory()

        # Check for probable configuration in the initial inventory
        probable_ciphers_initial = raw_inventory.get("services", {}).get("kubeadm", {}).get("apiServer", {}).get("extraArgs", {}).get("tls-cipher-suites")

        # Compare with desired ciphers
        desired_ciphers = "TLS_AES_128_GCM_SHA256,TLS_AES_256_GCM_SHA384,TLS_CHACHA20_POLY1305_SHA256,TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,TLS_RSA_WITH_3DES_EDE_CBC_SHA,TLS_RSA_WITH_AES_128_CBC_SHA,TLS_RSA_WITH_AES_128_GCM_SHA256,TLS_RSA_WITH_AES_256_CBC_SHA,TLS_RSA_WITH_AES_256_GCM_SHA384"
        if probable_ciphers_initial == desired_ciphers:
            cluster.log.info("API server already has the desired cipher suites in the initial inventory. Skipping patch.")
            return

        kubernetes_nodes = cluster.make_group_from_roles(['control-plane'])

        for member_node in kubernetes_nodes.get_ordered_members_list():
            apiserver_file = "/etc/kubernetes/manifests/kube-apiserver.yaml"

            # Load the YAML configuration
            try:
                apiserver_config = yaml.safe_load(member_node.sudo(f"cat {apiserver_file}").get_simple_out())
            except yaml.YAMLError as exc:
                cluster.log.error(f"Failed to parse YAML file: {exc}")
                continue

            # Check for any existing --tls-cipher-suites argument
            existing_ciphers_found = False
            for command in apiserver_config['spec']['containers'][0]['command']:
                if command.startswith("--tls-cipher-suites="):
                    existing_ciphers_found = True
                    break

            # Compare with desired ciphers
            if existing_ciphers_found:
                cluster.log.info("Skipping patch on this node as tls-cipher-suites are already present.")
                continue

            # Apply the patch
            apiserver_config['spec']['containers'][0]['command'].append("--tls-cipher-suites=TLS_AES_128_GCM_SHA256,TLS_AES_256_GCM_SHA384,TLS_CHACHA20_POLY1305_SHA256,TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,TLS_RSA_WITH_3DES_EDE_CBC_SHA,TLS_RSA_WITH_AES_128_CBC_SHA,TLS_RSA_WITH_AES_128_GCM_SHA256,TLS_RSA_WITH_AES_256_CBC_SHA,TLS_RSA_WITH_AES_256_GCM_SHA384")
            updated_config = yaml.dump(apiserver_config)
            member_node.put(StringIO(updated_config), apiserver_file, backup=True, sudo=True)

            # Call verify_apiserver_restart to check API server restart
            restart_successful = self.verify_apiserver_restart(member_node, res)

            if restart_successful:
                cluster.log.info("API server restart succeeded.")
            else:
                cluster.log.error("API server restart failed.") 

    def verify_apiserver_restart(self, member_node, res: DynamicResources) -> bool:
        # Implement logic to check API server restart status
        cluster = res.cluster()
        restart_successful = False

        # Get the creation timestamp of the kube-apiserver pod
        pod_creation_timestamp = member_node.run("sudo kubectl get pod -n kube-system -l component=kube-apiserver -o jsonpath='{.items[0].metadata.creationTimestamp}'")

        cluster.log.debug(f"Original pod creation timestamp: {pod_creation_timestamp}")

        # Optionally, force restart the kube-apiserver pod
        member_node.run("sudo kubectl delete pod -n kube-system -l component=kube-apiserver")

        # Wait for the new pod to be created
        time.sleep(10)  # Adjust the sleep time 

        # Get the new creation timestamp
        new_pod_creation_timestamp = member_node.run("sudo kubectl get pod -n kube-system -l component=kube-apiserver -o jsonpath='{.items[0].metadata.creationTimestamp}'")

        cluster.log.debug(f"New pod creation timestamp: {new_pod_creation_timestamp}")

        # Check if the creation timestamps are different
        if pod_creation_timestamp != new_pod_creation_timestamp:
            cluster.log.info("kube-apiserver pod has been restarted successfully.")
            restart_successful = True
        else:
            cluster.log.error("kube-apiserver pod restart failed.")

        return restart_successful

class ApiServerCipherSuites(RegularPatch):
    def __init__(self) -> None:
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
    
