import time


def override_priviledged_ports(cluster, service=None, namespace=None):
    cluster.log.debug('Unlocking privileged ports...')
    masters = cluster.nodes['master']
    masters.sudo('sed \'/- kube-apiserver/a\    - --service-node-port-range=80-32000\' -i /etc/kubernetes/manifests/kube-apiserver.yaml', hide=False)
    masters.sudo('systemctl restart kubelet.service', hide=False)
    # TODO: Get rid of hardcoded timeout - Wait for service start on all nodes
    time.sleep(60)
    masters.get_first_member().sudo('kubectl patch svc %s -n %s -p \'[ { "op": "replace", "path": "/spec/ports/1/nodePort", "value": 443 }, { "op": "replace", "path": "/spec/ports/0/nodePort", "value": 80 } ]\' --type=\'json\'' % (service, namespace), hide=False)
    masters.sudo('sed \'/service-node-port-range=.*/d\' -i /etc/kubernetes/manifests/kube-apiserver.yaml', hide=False)
    masters.sudo('systemctl restart kubelet.service', hide=False)
    time.sleep(60)
