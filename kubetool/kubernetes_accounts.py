import io

import yaml

from kubetool.core import utils


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
        cluster.log.debug('\tName: %s\n\tRole: %s\n\tNameSpace: %s' % (account['name'], account['role'], account['namespace']))

        dump = ''
        for config in account['configs']:
            dump += '---\n'+yaml.dump(config, default_flow_style=False)

        filename = 'account_%s_%s_%s.yaml' % (account['name'], account['role'], account['namespace'])
        destination_path = '/etc/kubernetes/%s' % filename

        utils.dump_file(cluster, dump, filename)

        cluster.log.debug("Uploading template...")
        cluster.log.debug("\tDestination: %s" % destination_path)
        cluster.nodes['master'].put(io.StringIO(dump), destination_path, sudo=True)

        cluster.log.debug("Applying yaml...")
        cluster.nodes['master'].get_first_member().sudo('kubectl apply -f %s' % destination_path, hide=False)

        # TODO: load all via api
        cluster.log.debug('Loading token...')
        load_tokens_cmd = 'kubectl -n kube-system get secret ' \
                          '$(sudo kubectl -n kube-system get sa %s -o \'jsonpath={.secrets[0].name}\') ' \
                          '-o \'jsonpath={.data.token}\' | sudo base64 -d' % account['name']
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
