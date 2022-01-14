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

import yaml

from kubemarine.core import utils


def enrich_inventory(inventory, cluster):
    rbac = inventory['rbac']
    if not rbac.get("accounts"):
        return inventory

    for i, account in enumerate(rbac["accounts"]):
        if account.get('name') is None or account.get('role') is None:
            raise Exception('Invalid account definition - name or role not defined')

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

    return inventory


def install(cluster):
    rbac = cluster.inventory['rbac']
    if not rbac.get("accounts"):
        cluster.log.debug("No accounts specified to install, skipping...")
        return

    tokens = []
    for account in rbac["accounts"]:
        cluster.log.debug('Creating cluster account:')
        cluster.log.debug(f"\tName: {account['name']}\n"
                          f"\tRole: {account['role']}\n"
                          f"\tNameSpace: {account['namespace']}")

        dump = ''
        for config in account['configs']:
            dump += '---\n'+yaml.dump(config, default_flow_style=False)

        filename = f"account_{account['name']}_{account['role']}_{account['namespace']}.yaml"
        destination_path = '/etc/kubernetes/%s' % filename

        utils.dump_file(cluster, dump, filename)

        cluster.log.debug("Uploading template...")
        cluster.log.debug("\tDestination: %s" % destination_path)
        cluster.nodes['master'].put(io.StringIO(dump), destination_path, sudo=True)

        cluster.log.debug("Applying yaml...")
        cluster.nodes['master'].get_first_member().sudo(f'kubectl apply -f {destination_path}',
                                                        hide=False)

        cluster.log.debug('Loading token...')
        load_tokens_cmd = f"kubectl -n kube-system get secret " \
                          f"$(sudo kubectl get sa {account['name']} " \
                          f"-n kube-system -o 'jsonpath={{.secrets[0].name}}') " \
                          f"-o 'jsonpath={{.data.token}}' | sudo base64 -d"
        result = cluster.nodes['master'].get_first_member().sudo(load_tokens_cmd)
        token = list(result.values())[0].stdout

        tokens.append({
            'name': account['name'],
            'role': account['role'],
            'namespace': account['namespace'],
            'token': token,
        })

    cluster.log.debug('\nSaving tokens...')
    token_filename = './account-tokens.yaml'
    with open(token_filename, 'w') as tokenfile:
        tokenfile.write(yaml.dump(tokens, default_flow_style=False))
        cluster.log.debug('Tokens saved to %s' % token_filename)
