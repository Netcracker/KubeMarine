# Copyright 2021-2022 NetCracker Technology Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import time


def override_priviledged_ports(cluster, service=None, namespace=None):
    cluster.log.debug('Unlocking privileged ports...')
    control_planes = cluster.nodes['control-plane']
    control_planes.sudo('sed \'/- kube-apiserver/a\    - --service-node-port-range=80-32000\' -i /etc/kubernetes/manifests/kube-apiserver.yaml', hide=False)
    control_planes.sudo('systemctl restart kubelet.service', hide=False)
    # TODO: Get rid of hardcoded timeout - Wait for service start on all nodes
    time.sleep(60)
    control_planes.get_first_member().sudo('kubectl patch svc %s -n %s -p \'[ { "op": "replace", "path": "/spec/ports/1/nodePort", "value": 443 }, { "op": "replace", "path": "/spec/ports/0/nodePort", "value": 80 } ]\' --type=\'json\'' % (service, namespace), hide=False)
    control_planes.sudo('sed \'/service-node-port-range=.*/d\' -i /etc/kubernetes/manifests/kube-apiserver.yaml', hide=False)
    control_planes.sudo('systemctl restart kubelet.service', hide=False)
    time.sleep(60)
