import io
from textwrap import dedent
import ruamel.yaml
import uuid
from kubemarine.core import utils
from kubemarine.core.action import Action
from kubemarine.core.patch import RegularPatch
from kubemarine.core.group import NodeGroup
from kubemarine.core.resources import DynamicResources

class TheAction(Action):
    def __init__(self) -> None:
        super().__init__("Update API Server TLS cipher suites (if necessary)")

    def run(self, res: DynamicResources) -> None:
        cluster = res.cluster()
        yaml = ruamel.yaml.YAML()
        tls_cipher_suites = "TLS_AES_128_GCM_SHA256,TLS_AES_256_GCM_SHA384,TLS_CHACHA20_POLY1305_SHA256,TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,TLS_RSA_WITH_3DES_EDE_CBC_SHA,TLS_RSA_WITH_AES_128_CBC_SHA,TLS_RSA_WITH_AES_128_GCM_SHA256,TLS_RSA_WITH_AES_256_CBC_SHA,TLS_RSA_WITH_AES_256_GCM_SHA384"
        kubernetes_nodes = cluster.make_group_from_roles(['control-plane'])

        for control_plane in kubernetes_nodes.get_ordered_members_list():
            # Read current kube-apiserver configuration
            result = control_plane.sudo("cat /etc/kubernetes/manifests/kube-apiserver.yaml")
            conf = yaml.load(list(result.values())[0].stdout)

            # Check for existing --tls-cipher-suites argument
            existing_ciphers = None
            for command in conf["spec"]["containers"][0]["command"]:
                if command.startswith("--tls-cipher-suites="):
                    existing_ciphers = command.split("=")[1]
                    break

            # Skip patch if ciphers are present
            if existing_ciphers:
                cluster.log.info("API server already has the cipher suites. Skipping patch.")
                continue

            # Apply the patch
            conf["spec"]["containers"][0]["command"].append("--tls-cipher-suites=%s" % tls_cipher_suites)
            
            # Updating kube-apiserver.yaml on control-plane
            buf = io.StringIO()
            yaml.dump(conf, buf)
            control_plane.put(buf, "/etc/kubernetes/manifests/kube-apiserver.yaml", sudo=True)

            # Restart kube-apiserver pod and wait for it to become available
            cri_runtime = control_plane.cluster.inventory['services']['cri']['containerRuntime']
            if cri_runtime == 'containerd':
                control_plane.call(utils.wait_command_successful, command="crictl rm -f "
                                                        "$(sudo crictl ps --name kube-apiserver -q)")
            else:
                control_plane.call(utils.wait_command_successful, command="docker stop "
                                                        "$(sudo docker ps -f 'name=k8s_kube-apiserver'"
                                                        " | awk '{print $1}')")
            control_plane.call(utils.wait_command_successful, command="kubectl get pod -n kube-system")
            
            # Call the update_kubeadm_configmap_tls_cipher_suites method
            self.update_kubeadm_configmap_tls_cipher_suites(control_plane, tls_cipher_suites)

    def update_kubeadm_configmap_tls_cipher_suites(self, control_plane, tls_cipher_suite) -> None:
        yaml = ruamel.yaml.YAML()
    
        # Retrieve current kubeadm config map
        result = control_plane.sudo("kubectl get cm kubeadm-config -n kube-system -o yaml")
        kubeadm_cm = yaml.load(list(result.values())[0].stdout)
        cluster_config = yaml.load(kubeadm_cm["data"]["ClusterConfiguration"])
    
        # Add or update tls-cipher-suites in the extraArgs section
        if 'extraArgs' not in cluster_config['apiServer']:
            cluster_config['apiServer']['extraArgs'] = {}
        cluster_config['apiServer']['extraArgs']['tls-cipher-suites'] = ruamel.yaml.scalarstring.PreservedScalarString(tls_cipher_suite)
    
        # Dump the updated config back to the kubeadm config map
        buf = io.StringIO()
        yaml.dump(cluster_config, buf)
        kubeadm_cm["data"]["ClusterConfiguration"] = buf.getvalue()
    
        # Apply the updated kubeadm config map
        buf = io.StringIO()
        yaml.dump(kubeadm_cm, buf)
        filename = uuid.uuid4().hex
        control_plane.put(buf, "/tmp/%s.yaml" % filename)
        control_plane.sudo("kubectl apply -f /tmp/%s.yaml" % filename)
        control_plane.sudo("rm -f /tmp/%s.yaml" % filename)

class UpdateApiServerCipherSuites(RegularPatch):
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
    
