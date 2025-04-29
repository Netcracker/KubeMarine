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
from textwrap import dedent
from typing import Optional

import yaml

from kubemarine.core import utils, summary
from kubemarine.core.cluster import KubernetesCluster, EnrichmentStage, enrichment


@enrichment(EnrichmentStage.FULL)
def enrich_inventory(cluster: KubernetesCluster) -> None:
    inventory = cluster.inventory
    rbac = inventory['rbac']
    if not rbac.get("accounts"):
        return

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

        if account['configs'][2]['metadata'].get('name') is None:
            rbac["accounts"][i]['configs'][2]['metadata']['annotations']['kubernetes.io/service-account.name'] \
                = account['name']
            rbac["accounts"][i]['configs'][2]['metadata']['name'] = f"{account['name']}-token"
            rbac["accounts"][i]['configs'][0]['secrets'].append({})
            rbac["accounts"][i]['configs'][0]['secrets'][0]['name'] = f"{account['name']}-token"
        if account['configs'][2]['metadata'].get('namespace') is None:
            rbac["accounts"][i]['configs'][2]['metadata']['namespace'] = account['namespace']


def handle_authenticated_sa_issuer_discovery(cluster: KubernetesCluster) -> None:
    """
    This function handles SA issuer discovery endpoint authentication

    To disable authentication, we apply CRB which allows unauthenticated access.
    To enable authentication, we delete above CRB (if it is present).

    For more information on the cluster role: 
    https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/#service-account-issuer-discovery
    """
    mode = "unauthenticated"
    kubectl_cmd = "apply"
    if cluster.inventory.get("rbac", {}).get("authenticated-issuer-discovery", False):
        mode = "authenticated"
        kubectl_cmd = "delete --ignore-not-found"
    issuer_discovery_crb = dedent("""\
        kind: ClusterRoleBinding
        apiVersion: rbac.authorization.k8s.io/v1
        metadata:
          name: kubemarine-unauthenticated-service-account-issuer-discovery
        subjects:
        - apiGroup: rbac.authorization.k8s.io
          kind: Group
          name: system:unauthenticated
        roleRef:
          apiGroup: rbac.authorization.k8s.io
          kind: ClusterRole
          name: system:service-account-issuer-discovery
    """)

    cluster.log.debug(f"Configuring {mode} service account issuer discovery...")
    tmp_path = utils.get_remote_tmp_path()
    node = cluster.nodes['control-plane'].get_first_member()
    node.put(io.StringIO(issuer_discovery_crb), tmp_path, sudo=True)
    node.sudo(f"kubectl {kubectl_cmd} -f {tmp_path}", hide=False)


def install(cluster: KubernetesCluster) -> None:
    # issuer discovery authentication is handled as part of deploy.accounts,
    # because deploy.accounts is safe to re-run (idempotent) and
    # discovery authentication does not worth a separate install task
    handle_authenticated_sa_issuer_discovery(cluster)

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

        token: Optional[str] = None
        retries = cluster.globals['accounts']['retries']
        # Token creation is not synchronous, therefore retries are necessary
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
    token_filename = utils.get_external_resource_path('account-tokens.yaml')
    utils.dump_file(cluster.context, yaml.dump(tokens), token_filename, dump_location=False)
    cluster.log.debug('Tokens saved to %s' % token_filename)

    summary.schedule_report(cluster.context, summary.SummaryItem.ACCOUNT_TOKENS, token_filename)
