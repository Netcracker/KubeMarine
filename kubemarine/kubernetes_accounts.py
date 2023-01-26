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

import io
import os

import yaml

from kubemarine.core import utils, summary
from kubemarine.core.cluster import KubernetesCluster


def enrich_inventory(inventory, cluster):
    rbac = inventory['rbac']
    if not rbac.get("accounts"):
        return inventory

    for i, account in enumerate(rbac["accounts"]):
        if account['configs'][0]['metadata'].get('name') is None:
            rbac["accounts"][i]['configs'][0]['metadata']['name'] = account['name']
        if account['configs'][0]['metadata'].get('namespace') is None:
            rbac["accounts"][i]['configs'][0]['metadata']['namespace'] = account['namespace']

        if account['configs'][1]['metadata'].get('name') is None:
            rbac["accounts"][i]['configs'][1]['metadata']['name'] = account['name']
        if account['configs'][1]['roleRef'].get('name') is None:
            rbac["accounts"][i]['configs'][1]['roleRef']['name'] = account['role']

        if account['configs'][1]['subjects'][0].get('name') is None:
            rbac["accounts"][i]['configs'][1]['subjects'][0]['name'] = account['name']
        if account['configs'][1]['subjects'][0].get('namespace') is None:
            rbac["accounts"][i]['configs'][1]['subjects'][0]['namespace'] = account['namespace']

        # For Kubernetes v1.23 and lower are used legacy enrichment
        # It has only 'ServiceAccount' and 'ClusterRoleBinding'
        minor_version = int(inventory["services"]["kubeadm"]["kubernetesVersion"].split('.')[1])
        if minor_version < 24:
            if len(rbac["accounts"][i]['configs']) > 2:
                rbac["accounts"][i]['configs'].pop(2)
            if rbac["accounts"][i]['configs'][0].get('secrets') is not None:
                rbac["accounts"][i]['configs'][0].pop('secrets')
        else:
           # This part is applicable for Kubernetes v1.24 and higher
           # It has 'Secret' in addition 
            if account['configs'][2]['metadata'].get('name') is None:
                rbac["accounts"][i]['configs'][2]['metadata']['annotations']['kubernetes.io/service-account.name'] = account['name']
                rbac["accounts"][i]['configs'][2]['metadata']['name'] = f"{account['name']}-token"
                rbac["accounts"][i]['configs'][0]['secrets'].append({})
                rbac["accounts"][i]['configs'][0]['secrets'][0]['name'] = f"{account['name']}-token"
            if account['configs'][2]['metadata'].get('namespace') is None:
                rbac["accounts"][i]['configs'][2]['metadata']['namespace'] = account['namespace']

    return inventory


def install(cluster: KubernetesCluster):
    rbac = cluster.inventory['rbac']
    if not rbac.get("accounts"):
        cluster.log.debug("No accounts specified to install, skipping...")
        return

    tokens = []
    for account in rbac["accounts"]:
        cluster.log.debug('Creating cluster account:')
        cluster.log.debug('\tName: %s\n\tRole: %s\n\tNameSpace: %s' % (account['name'], account['role'], account['namespace']))

        dump = ''
        for config in account['configs']:
            dump += '---\n'+yaml.dump(config, default_flow_style=False)

        filename = 'account_%s_%s_%s.yaml' % (account['name'], account['role'], account['namespace'])
        destination_path = '/etc/kubernetes/%s' % filename

        utils.dump_file(cluster, dump, filename)

        cluster.log.debug("Uploading template...")
        cluster.log.debug("\tDestination: %s" % destination_path)
        cluster.nodes['control-plane'].put(io.StringIO(dump), destination_path, sudo=True)

        cluster.log.debug("Applying yaml...")
        cluster.nodes['control-plane'].get_first_member().sudo('kubectl apply -f %s' % destination_path, hide=False)

        cluster.log.debug('Loading token...')
        load_tokens_cmd = 'kubectl -n %s get secret ' \
                          '$(sudo kubectl -n %s get sa %s -o \'jsonpath={.secrets[0].name}\') -o \'jsonpath={.data.token}\'' \
                          '| sudo base64 -d' % (account['namespace'], account['namespace'], account['name'])

        token = []
        retries = cluster.globals['accounts']['retries']
        # Token creation in Kubernetes 1.24 is not syncronus, therefore retries are necessary
        while retries > 0:
            result = cluster.nodes['control-plane'].get_first_member().sudo(load_tokens_cmd)
            token = list(result.values())[0].stdout
            if not token:
                retries -= 1
            else:
                break
        if not token:
            raise Exception(f"The token loading for {account['name']} 'ServiceAccount' failed")

        tokens.append({
            'name': account['name'],
            'role': account['role'],
            'namespace': account['namespace'],
            'token': token,
        })

    cluster.log.debug('\nSaving tokens...')
    token_filename = os.path.abspath('account-tokens.yaml')
    with utils.open_external(token_filename, 'w') as tokenfile:
        tokenfile.write(yaml.dump(tokens, default_flow_style=False))
        cluster.log.debug('Tokens saved to %s' % token_filename)

    summary.schedule_report(cluster.context, summary.SummaryItem.ACCOUNT_TOKENS, token_filename)
