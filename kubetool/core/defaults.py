#!/usr/bin/env python3

import re
from importlib import import_module
from copy import deepcopy

import yaml

from kubetool import jinja
from kubetool.core import utils
from kubetool.core.yaml_merger import default_merger

DEFAULT_ENRICHMENT_FNS = [
    "kubetool.kubernetes.add_node_enrichment",
    "kubetool.kubernetes.remove_node_enrichment",
    "kubetool.core.defaults.append_controlplain",
    "kubetool.kubernetes.enrich_upgrade_inventory",
    "kubetool.plugins.enrich_upgrade_inventory",
    "kubetool.packages.enrich_inventory_associations",
    "kubetool.system.enrich_upgrade_inventory",
    "kubetool.core.defaults.compile_inventory",
    "kubetool.psp.manage_psp_enrichment",
    "kubetool.thirdparties.enrich_inventory_apply_upgrade_defaults",
    "kubetool.procedures.migrate_cri.enrich_inventory",
    "kubetool.core.defaults.apply_registry",
    "kubetool.core.defaults.calculate_node_names",
    "kubetool.core.defaults.verify_node_names",
    "kubetool.core.defaults.apply_defaults",
    "kubetool.keepalived.enrich_inventory_apply_defaults",
    "kubetool.haproxy.enrich_inventory",
    "kubetool.kubernetes.enrich_inventory",
    "kubetool.psp.enrich_inventory",
    "kubetool.kubernetes_accounts.enrich_inventory",
    "kubetool.plugins.calico.enrich_inventory",
    "kubetool.plugins.nginx_ingress.cert_renew_enrichment",
    "kubetool.plugins.nginx_ingress.verify_inventory",
    "kubetool.plugins.nginx_ingress.enrich_inventory",
    "kubetool.core.defaults.calculate_nodegroups",
    "kubetool.keepalived.enrich_inventory_calculate_nodegroup",
    "kubetool.thirdparties.enrich_inventory_apply_defaults",
    "kubetool.system.verify_inventory",
    "kubetool.system.enrich_inventory",
    "kubetool.selinux.verify_inventory",
    "kubetool.apparmor.verify_inventory",
    "kubetool.plugins.enrich_inventory",
    "kubetool.plugins.verify_inventory",
    "kubetool.coredns.enrich_add_hosts_config",
    "kubetool.k8s_certs.renew_verify",
    "kubetool.cri.enrich_inventory"
]

supported_defaults = {
    'rbac': {
        'account_defaults': 'accounts'
    },
    'node_defaults': 'nodes',
    'plugin_defaults': 'plugins',
}

invalid_node_name_regex = re.compile("[^a-z-.\\d]", re.M)
escaped_expression_regex = re.compile('({%[\\s*|]raw[\\s*|]%}.*?{%[\\s*|]endraw[\\s*|]%})', re.M)


def apply_defaults(inventory, cluster):
    recursive_apply_defaults(supported_defaults, inventory)

    for i, node in enumerate(inventory["nodes"]):

        node_name = node.get("name")
        if node_name is None:
            raise Exception('Some nodes from inventory are unnamed')

        if re.findall(invalid_node_name_regex, node_name):
            raise Exception('Node name \"%s\" contains invalid characters. A DNS-1123 subdomain must consist of lower '
                            'case alphanumeric characters, \'-\' or \'.\'' % node_name)

        address = node.get('connect_to')
        if address is None:
            address = node.get('address')
        if address is None:
            address = node.get('internal_address')
        if address is None:
            raise Exception('Node %s do not have any address' % node_name)

        # we have definitely know how to connect
        cluster.inventory["nodes"][i]["connect_to"] = address
        cluster.inventory["nodes"][i]["connection"] = cluster.make_group([address])

        if not cluster.context["nodes"].get(address):
            cluster.context["nodes"][address] = {}

        if not node.get("roles"):
            raise Exception('There are no roles defined for the node %s' % node_name)

        if address not in cluster.ips["all"]:
            cluster.ips['all'].append(address)

        for role in node.get("roles"):
            if role not in cluster.supported_roles:
                raise Exception('An unknown role defined for the node %s' % node_name)
            if role not in cluster.roles:
                cluster.roles.append(role)
                cluster.ips[role] = []
            if address not in cluster.ips[role]:
                cluster.ips[role].append(address)

    return inventory


def apply_registry(inventory, cluster):

    if not inventory.get('registry', {}).get('address'):
        cluster.log.verbose('Unified registry is not used')
        return inventory

    if inventory['registry'].get('docker_port'):
        full_registry_address = "%s:%s" % (inventory['registry']['address'], inventory['registry']['docker_port'])
    else:
        full_registry_address = inventory['registry']['address']

    protocol = 'http'
    if inventory['registry'].get('ssl', False):
        protocol = 'https'

    # Patch kubeadm imageRepository
    if not inventory['services']['kubeadm'].get('imageRepository'):
        inventory['services']['kubeadm']["imageRepository"] = full_registry_address
        if inventory['registry'].get('webserver', False):
            # it is necessary to search in example.com:XXXX/k8s.gcr.io because images from other hubs located in
            # directory with the hub name
            inventory['services']['kubeadm']["imageRepository"] += "/k8s.gcr.io"

    # it is necessary to convert URIs from quay.io/xxx:v1 to example.com:XXXX/quay.io/xxx:v1
    if inventory.get('plugin_defaults') is None:
        inventory['plugin_defaults'] = {}
    if inventory['plugin_defaults'].get('installation') is None:
        inventory['plugin_defaults']['installation'] = {}
    if not inventory['plugin_defaults']['installation'].get('registry'):
        inventory['plugin_defaults']['installation']['registry'] = full_registry_address

    cri_impl = inventory['services']['cri']['containerRuntime']
    if cri_impl == "docker":
        if not inventory['registry'].get('ssl', False):
            if inventory['services']['cri']['dockerConfig'].get("insecure-registries") is None:
                inventory['services']['cri']['dockerConfig']["insecure-registries"] = []
            insecure_registries = inventory['services']['cri']['dockerConfig']["insecure-registries"]
            insecure_registries.append(full_registry_address)
            inventory['services']['cri']['dockerConfig']["insecure-registries"] = list(set(insecure_registries))

        if inventory['services']['cri']['dockerConfig'].get("registry-mirrors") is None:
            inventory['services']['cri']['dockerConfig']["registry-mirrors"] = []
        registry_mirrors = inventory['services']['cri']['dockerConfig']["registry-mirrors"]
        registry_mirrors.append(f"{protocol}://{full_registry_address}")
        inventory['services']['cri']['dockerConfig']["registry-mirrors"] = list(set(registry_mirrors))
    elif cri_impl == "containerd":
        registry_section = f'plugins."io.containerd.grpc.v1.cri".registry.mirrors."{full_registry_address}"'
        if not inventory['services']['cri']['containerdConfig'].get(registry_section):
            inventory['services']['cri']['containerdConfig'][registry_section] = {
                'endpoint': ["%s://%s" % (protocol, full_registry_address)]
            }
        if not inventory['services']['cri']['containerdConfig'].get('plugins."io.containerd.grpc.v1.cri"'):
            inventory['services']['cri']['containerdConfig']['plugins."io.containerd.grpc.v1.cri"'] = {}
        if not inventory['services']['cri']['containerdConfig']['plugins."io.containerd.grpc.v1.cri"'].get('sandbox_image'):
            inventory['services']['cri']['containerdConfig']['plugins."io.containerd.grpc.v1.cri"']['sandbox_image'] = \
                f"{inventory['services']['kubeadm']['imageRepository']}/pause:3.2"

    if inventory['registry'].get('webserver', False) and inventory['services'].get('thirdparties', []):
        for destination, config in inventory['services']['thirdparties'].items():

            if isinstance(config, str):
                new_source = inventory['services']['thirdparties'][destination]
            elif config.get('source') is not None:
                new_source = inventory['services']['thirdparties'][destination]['source']
            else:
                continue

            for binary in ['kubeadm', 'kubelet', 'kubectl']:
                if destination == '/usr/bin/' + binary:
                    new_source = new_source.replace('https://storage.googleapis.com/kubernetes-release/release',
                                                    '%s://%s/kubernetes/%s'
                                                    % (protocol, inventory['registry']['address'], binary))

            if '/usr/bin/calicoctl' == destination:
                new_source = new_source.replace('https://github.com/projectcalico/calicoctl/releases/download',
                                                '%s://%s/projectcalico/calicoctl'
                                                % (protocol, inventory['registry']['address']))

            if '/usr/bin/crictl.tar.gz' == destination:
                new_source = new_source.replace('https://github.com/kubernetes-sigs/cri-tools/releases/download',
                                                '%s://%s/kubernetes-sigs/cri-tools'
                                                % (protocol, inventory['registry']['address']))
            if isinstance(config, str):
                inventory['services']['thirdparties'][destination] = new_source
            else:
                inventory['services']['thirdparties'][destination]['source'] = new_source

    return inventory


def append_controlplain(inventory, cluster):

    if inventory.get('control_plain', {}).get('internal') and inventory.get('control_plain', {}).get('external'):
        if cluster:
            cluster.log.verbose('Control plains are set manually, nothing to detect.')
        return inventory

    if cluster:
        cluster.log.verbose('Detecting control plains...')

    # calculate controlplain ips
    internal_address = None
    internal_address_source = None
    external_address = None
    external_address_source = None

    # vrrp_ip section is not enriched yet
    # todo what if ip is an ip of some node to remove?
    if inventory.get('vrrp_ips'):
        for i, item in enumerate(inventory['vrrp_ips']):
            if isinstance(item, str):
                if internal_address is None:
                    internal_address = item
                    internal_address_source = 'vrrp_ip[%s]' % i
            else:
                if internal_address is None or item.get('control_endpoint', False):
                    internal_address = item['ip']
                    internal_address_source = 'vrrp_ip[%s]' % i
                if item.get('floating_ip') and (external_address is None or item.get('control_endpoint', False)):
                    external_address = item['floating_ip']
                    external_address_source = 'vrrp_ip[%s]' % i

    if internal_address is not None and external_address is None and cluster:
        cluster.log.warning('VRRP_IPs has an internal address, but do not have an external one. Your configuration may be incorrect. Trying to handle this problem automatically...')

    if internal_address is None or external_address is None:
        for role in ['balancer', 'master']:
            # nodes are not compiled to groups yet
            for node in inventory['nodes']:
                if role in node['roles'] and 'remove_node' not in node['roles']:
                    if internal_address is None or node.get('control_endpoint', False):
                        internal_address = node['internal_address']
                        internal_address_source = role
                        if node.get('name'):
                            internal_address_source += ' \"%s\"' % node['name']
                    if node.get('address') and (external_address is None or node.get('control_endpoint', False)):
                        external_address = node['address']
                        external_address_source = role
                        if node.get('name'):
                            external_address_source += ' \"%s\"' % node['name']

    if external_address is None:
        cluster.log.warning('Failed to detect external control plain. Something may work incorrect!')
        external_address = internal_address

    if cluster:
        cluster.log.debug('Control plains:\n   Internal: %s (%s)\n   External: %s (%s)' % (internal_address, internal_address_source, external_address, external_address_source))

    # apply controlplain ips
    if not inventory.get('control_plain'):
        inventory['control_plain'] = {}

    if not inventory['control_plain'].get('internal'):
        inventory['control_plain']['internal'] = internal_address

    if not inventory['control_plain'].get('external'):
        inventory['control_plain']['external'] = external_address

    return inventory


def recursive_apply_defaults(defaults, section):
    for key, value in defaults.items():
        if isinstance(value, dict) and section.get(key) is not None and section[key]:
            recursive_apply_defaults(value, section[key])
        # check if target section exists and not empty
        elif section.get(value) is not None and section[value]:

            if isinstance(section[value], list):
                for i, v in enumerate(section[value]):
                    # copy defaults as new dict, to avoid problems with memory links
                    node_config = deepcopy(section[key])

                    # update defaults with custom-defined node configs
                    # TODO: deepmerge required here
                    node_config.update(v)

                    # replace old node config with merged one
                    section[value][i] = node_config

            else:
                # deepcopy the whole section, otherwise it will break dict while replacing
                section_copy = deepcopy(section[value])
                for custom_key, custom_value in section_copy.items():
                    # here section['key'] refers to default, not custom value
                    default_value = deepcopy(section[key])
                    section[value][custom_key] = default_merger.merge(default_value, custom_value)

            del section[key]


def calculate_node_names(inventory, cluster):
    roles_iterators = {}
    for i, node in enumerate(inventory['nodes']):
        for role_name in ['master', 'worker', 'balancer']:
            if role_name in node.get('roles', []):
                # The idea is this:
                # If the name is already specified, we must skip this node,
                # however, we must consider that we already have a node of this type
                # and increase this type iterator
                # As a result, we get such an algorithm. For example, with the following inventory:
                #
                # - name: k8s-master-1, roles: ['master']
                # - roles: ['master']
                # - name: k8s-master-3, roles: ['master']
                #
                # We should get the following calculation result:
                #
                # - name: k8s-master-1, roles: ['master']
                # - name: master-2, roles: ['master']
                # - name: k8s-master-3, roles: ['master']
                #
                role_i = roles_iterators.get(role_name, 1)
                roles_iterators[role_name] = role_i + 1
                if node.get('name') is None:
                    inventory['nodes'][i]['name'] = '%s-%s' % (role_name, role_i)
    return inventory


def verify_node_names(inventory, cluster):
    known_names = []
    for i, node in enumerate(inventory['nodes']):
        if node.get('name') is None:
            raise Exception('Node item %s in nodes section do not contain name' % i)
        if node['name'] in known_names:
            raise Exception('Node name %s is duplicated in configfile' % node['name'])
        known_names.append(node['name'])
    return inventory


def calculate_nodegroups(inventory, cluster):
    for role in cluster.ips.keys():
        cluster.nodes[role] = cluster.make_group(cluster.ips[role])
    return inventory


def enrich_inventory(cluster, custom_inventory, apply_fns=True, make_dumps=True, custom_fns=None):
    with open(utils.get_resource_absolute_path('resources/configurations/defaults.yaml',
                                               script_relative=True), 'r') as stream:
        base_inventory = yaml.safe_load(stream)

        inventory = default_merger.merge(base_inventory, custom_inventory)

        # it is necessary to temporary put half-compiled inventory to cluster inventory field
        cluster._inventory = inventory
        if apply_fns:
            if custom_fns:
                enrichment_functions = custom_fns
            else:
                enrichment_functions = DEFAULT_ENRICHMENT_FNS

            # run required fields calculation
            for enrichment_fn in enrichment_functions:
                fn_package_name, fn_method_name = enrichment_fn.rsplit('.', 1)
                mod = import_module(fn_package_name)
                cluster.log.verbose('Calling fn "%s"' % enrichment_fn)
                inventory = getattr(mod, fn_method_name)(inventory, cluster)

        cluster.log.verbose('Enrichment finished!')

        if make_dumps:
            utils.dump_file(cluster, yaml.dump(prepare_for_dump(inventory), ), "cluster.yaml")
            procedure_config = cluster.context["execution_arguments"].get("procedure_config")
            if procedure_config:
                with open(procedure_config, 'r') as stream:
                    utils.dump_file(cluster, stream, "procedure.yaml")

        return inventory


def compile_inventory(inventory, cluster):

    # convert references in yaml to normal values
    iterations = 100
    root = deepcopy(inventory)
    root['globals'] = cluster.globals

    while iterations > 0:

        cluster.log.verbose('Inventory is not rendered yet...')
        inventory = compile_object(cluster.log, inventory, root)

        temp_dump = yaml.dump(inventory)

        # remove golang specific
        temp_dump = re.sub(escaped_expression_regex, '', temp_dump.replace('\n', ''))

        # it is necessary to carry out several iterations,
        # in case we have dynamic variables that reference each other
        if '{{' in temp_dump or '{%' in temp_dump:
            iterations -= 1
        else:
            iterations = 0

    inventory = compile_object(cluster.log, inventory, root, ignore_jinja_escapes=False)

    merged_inventory = yaml.dump(prepare_for_dump(inventory))
    utils.dump_file(cluster, merged_inventory, "cluster_precompiled.yaml")

    return inventory


def compile_object(log, struct, root, ignore_jinja_escapes=True):
    if isinstance(struct, list):
        for i, v in enumerate(struct):
            struct[i] = compile_object(log, v, root, ignore_jinja_escapes=ignore_jinja_escapes)
    elif isinstance(struct, dict):
        for k, v in struct.items():
            struct[k] = compile_object(log, v, root, ignore_jinja_escapes=ignore_jinja_escapes)
    elif isinstance(struct, str) and ('{{' in struct or '{%' in struct):
        struct = compile_string(log, struct, root, ignore_jinja_escapes=ignore_jinja_escapes)
    return struct


def compile_string(log, struct, root, ignore_jinja_escapes=True):
    log.verbose("Rendering \"%s\"" % struct)

    if ignore_jinja_escapes:
        iterator = escaped_expression_regex.finditer(struct)
        struct = re.sub(escaped_expression_regex, '', struct)
        struct = jinja.new(log, root).from_string(struct).render(**root)

        for match in iterator:
            span = match.span()
            struct = struct[:span[0]] + match.group() + struct[span[0]:]
    else:
        struct = jinja.new(log, root).from_string(struct).render(**root)

    log.verbose("\tRendered as \"%s\"" % struct)
    return struct


def prepare_for_dump(inventory, copy=True):
    # preparation for dump required to remove memory links

    if copy:
        dump_inventory = deepcopy(inventory)
    else:
        dump_inventory = inventory

    for i, node in enumerate(dump_inventory['nodes']):
        if 'connection' in dump_inventory['nodes'][i]:
            del dump_inventory['nodes'][i]['connection']

    return dump_inventory

