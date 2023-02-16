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
import ipaddress
import ruamel.yaml
import os

from copy import deepcopy

from kubemarine import plugins
from kubemarine.core import utils



def enrich_inventory(inventory, cluster):

    # By default we use calico, but have to find it out
    # First of all we have to check is Calicon set to be installed or not
    # By default installation parameter is unset, means user did not made any decision
    if inventory["plugins"]["calico"].get("install") is None:
        # Is user defined Flannel plugin and set it to install?
        flannel_required = inventory["plugins"].get("flannel", {}).get("install", False)
        # Is user defined Canal plugin and set it to install?
        canal_required = inventory["plugins"].get("canal", {}).get("install", False)
        # If Flannel and Canal is unset or not required to install, then install Calico
        if not flannel_required and not canal_required:
            inventory["plugins"]["calico"]["install"] = True

    if inventory["plugins"]["calico"]["install"]:
        # Check if original YAML exists
        items = inventory['plugins']['calico']['installation']['procedures']
        for item in items:
            if item.get('python'):
                # create config for plugin module
                calico_original_yaml = item['python']["arguments"]["calico_original_yaml"]
                config = {
                    "source": calico_original_yaml
                }
                calico_original_yaml_path, _ = plugins.get_source_absolute_pattern(config)
                if not os.path.isfile(calico_original_yaml_path):
                    raise Exception(f"Cannot find original Calico manifest {calico_original_yaml_path}")

    return inventory


def apply_calico_yaml(cluster, calico_original_yaml, calico_yaml):
    """
    The method implements full proccessing for Calico plugin
    :param calico_original_yaml: path to original Calico manifest
    :param calico_yaml: file name of the resulting Calico manifest
    :param cluster: Cluster object
    """

    calico_yaml = os.path.basename(calico_yaml)
    destination = '/etc/kubernetes/%s' % calico_yaml

    # create config for plugin module
    config = {
        "source": calico_original_yaml,
        "destination": destination,
        "do_render": False
    }

    # get original YAML and parse it into dict of objects
    calico_original_yaml_path, _ = plugins.get_source_absolute_pattern(config)
    obj_list = load_multiple_yaml(calico_original_yaml_path, cluster)

    validate_original(cluster, obj_list)

    patched_list = []
    excluded_list = []

    # list of objects for enrichment
    objects_for_enrichment = [
            "ConfigMap_calico-config",
            "Deployment_calico-kube-controllers",
            "DaemonSet_calico-node",
            "Deployment_calico-typha",
            "Service_calico-typha", 
            "PodDisruptionBudget_calico-typha",
            "ClusterRole_calico-kube-controllers",
            "ClusterRole_calico-node"
           ]

    # enrich objects one by one
    for key in objects_for_enrichment:
        # enrich common Calico objects
        if key not in ["Service_calico-typha", "PodDisruptionBudget_calico-typha", "Deployment_calico-typha"]:
            if obj_list.get(key, ''):
                patched_list.append(key)
                obj_list = enrich_objects_fns[key](cluster, obj_list)
        else:
            # enrich 'calico-typha' objects only if it's enabled in 'cluster.yaml'
            # in other case those objects must be excluded
            str_value = utils.true_or_false(cluster.inventory['plugins']['calico']['typha']['enabled'])
            if str_value == 'false':
                obj_list.pop(key)
                excluded_list.append(key)
                cluster.log.verbose(f"The {key} has been excluded from result")
            elif str_value == 'true':
                patched_list.append(key)
                if enrich_objects_fns[key]:
                    obj_list = enrich_objects_fns[key](cluster, obj_list)
            else:
                raise Exception(f"The {key} can't be patched correctly "
                                f"plugins.calico.typha.enabled must be set in 'True' or 'False' "
                                f"as string or boolean value")

    cluster.log.verbose(f"The total number of patched objects is {len(patched_list)} "
                        f"the objects are the following: {patched_list}")
    cluster.log.verbose(f"The total number of excluded objects is {len(excluded_list)} "
                        f"the objects are the following: {excluded_list}")

    # TODO: check results 
    #validate_result()
    enriched_manifest = dump_multiple_yaml(obj_list)
    utils.dump_file(cluster, enriched_manifest, calico_yaml)
    config['source'] = io.StringIO(enriched_manifest)

    cluster.log.debug("Uploading calico manifest enriched from %s ..." % calico_original_yaml_path)
    cluster.log.debug("\tDestination: %s" % destination)

    plugins.apply_source(cluster, config)


def enrich_configmap_calico_config(cluster, obj_list):
    """
    The method implements the enrichment procedure for Calico ConfigMap
    :param cluster: Cluster object
    :param obj_list: list of objects for enrichment
    """

    key = "ConfigMap_calico-config"
    val = cluster.inventory['plugins']['calico']['mtu']
    obj_list[key]['data']['veth_mtu'] = str(val)
    cluster.log.verbose(f"The {key} has been patched in 'data.veth_mtu' with '{val}'")
    str_value = utils.true_or_false(cluster.inventory['plugins']['calico']['typha']['enabled'])
    if str_value == "true":
        val = "calico-typha"
    elif str_value == "false":
        val = "none"
    obj_list[key]['data']['typha_service_name'] = val
    cluster.log.verbose(f"The {key} has been patched in 'data.typha_service_name' with '{val}'")
    string_part = obj_list[key]['data']['cni_network_config']
    ip = cluster.inventory['services']['kubeadm']['networking']['podSubnet'].split('/')[0]
    if type(ipaddress.ip_address(ip)) is ipaddress.IPv4Address:
        val = cluster.inventory['plugins']['calico']['cni']['ipam']['ipv4']
    else:
        val = cluster.inventory['plugins']['calico']['cni']['ipam']['ipv6']
    new_string_part = string_part.replace('"type": "calico-ipam"', str(val)[:-1][1:].replace("'", "\""))
    obj_list[key]['data']['cni_network_config'] = new_string_part
    log_str = new_string_part.replace("\n", "")
    cluster.log.verbose(f"The {key} has been patched in 'data.cni_network_config' with '{log_str}'")
    
    return obj_list

def enrich_deployment_calico_kube_controllers(cluster, obj_list):
    """
    The method implements the enrichment procedure for Calico controller Deployment
    :param cluster: Cluster object
    :param obj_list: list of objects for enrichment
    """

    key = "Deployment_calico-kube-controllers"
    obj_list[key]['spec']['template']['spec']['nodeSelector'] = \
            cluster.inventory['plugins']['calico']['kube-controllers']['nodeSelector']
    for container in obj_list[key]['spec']['template']['spec']['containers']:
        if container['name'] == "calico-kube-controllers":
            num = obj_list[key]['spec']['template']['spec']['containers'].index(container)
            val = enrich_image(cluster, cluster.inventory['plugins']['calico']['kube-controllers']['image'])
            obj_list[key]['spec']['template']['spec']['containers'][num]['image'] = val
            cluster.log.verbose(f"The {key} has been patched in "
                                f"'spec.template.spec.containers.[{num}].image with '{val}'")

    return obj_list

def enrich_daemonset_calico_node(cluster, obj_list):
    """
    The method implements the enrichment procedure for Calico node DaemonSet
    :param cluster: Cluster object
    :param obj_list: list of objects for enrichment
    """

    key = "DaemonSet_calico-node"
    for container in obj_list[key]['spec']['template']['spec']['initContainers']:
        if container['name'] in ['upgrade-ipam', 'install-cni']: 
            num = obj_list[key]['spec']['template']['spec']['initContainers'].index(container)
            val = enrich_image(cluster, cluster.inventory['plugins']['calico']['cni']['image'])
            obj_list[key]['spec']['template']['spec']['initContainers'][num]['image'] = val
            cluster.log.verbose(f"The {key} has been patched in "
                                f"'spec.template.spec.initContainers.[{num}].image' with '{val}'")
        if container['name'] == "mount-bpffs":
            num = obj_list[key]['spec']['template']['spec']['initContainers'].index(container)
            val = enrich_image(cluster, cluster.inventory['plugins']['calico']['node']['image'])
            obj_list[key]['spec']['template']['spec']['initContainers'][num]['image'] = val
            cluster.log.verbose(f"The {key} has been patched in "
                                f"'spec.template.spec.initContainers.[{num}].image' with '{val}'")
        if container['name'] == "flexvol-driver":
            num = obj_list[key]['spec']['template']['spec']['initContainers'].index(container)
            val = enrich_image(cluster, cluster.inventory['plugins']['calico']['flexvol']['image'])
            obj_list[key]['spec']['template']['spec']['initContainers'][num]['image'] = val
            cluster.log.verbose(f"The {key} has been patched in "
                                f"'spec.template.spec.initContainers.[{num}].image' with '{val}'")
    for container in obj_list[key]['spec']['template']['spec']['containers']:
        if container['name'] == "calico-node":
            num = obj_list[key]['spec']['template']['spec']['containers'].index(container)
            val = enrich_image(cluster, cluster.inventory['plugins']['calico']['node']['image'])
            obj_list[key]['spec']['template']['spec']['containers'][num]['image'] = val 
            cluster.log.verbose(f"The {key} has been patched in "
                                f"'spec.template.spec.containers.[{num}].image' with '{val}'")
            ipv6_env = ['CALICO_IPV6POOL_CIDR', 'IP6', 'IP6_AUTODETECTION_METHOD', 'FELIX_IPV6SUPPORT', 
                        'CALICO_IPV6POOL_IPIP', 'CALICO_IPV6POOL_VXLAN']
            env_list = []
            for name, value in cluster.inventory['plugins']['calico']['env'].items():
                ip = cluster.inventory['services']['kubeadm']['networking']['podSubnet'].split('/')[0]
                if name not in ipv6_env and name != 'FELIX_TYPHAK8SSERVICENAME':
                    if type(value) is str:
                        env_list.append({'name': name, 'value': value})
                    elif type(value) is dict:
                        env_list.append({'name': name, 'valueFrom': value})
                    cluster.log.verbose(f"The {key} has been patched in "
                                        f"'spec.template.spec.containers.[{num}].env.{name}' with '{value}'")
                elif name in ipv6_env and type(ipaddress.ip_address(ip)) is not ipaddress.IPv4Address:
                    if type(value) is str:
                        env_list.append({'name': name, 'value': value})
                    elif type(value) is dict:
                        env_list.append({'name': name, 'valueFrom': value})
                    cluster.log.verbose(f"The {key} has been patched in "
                                        f"'spec.template.spec.containers.[{num}].env.{name}' with '{value}'")
                if utils.true_or_false(cluster.inventory['plugins']['calico']['typha']['enabled']) == "true" and \
                        name == 'FELIX_TYPHAK8SSERVICENAME':
                    env_list.append({'name': name, 'valueFrom': value})
                    cluster.log.verbose(f"The {key} has been patched in "
                                        f"'spec.template.spec.containers.[{num}].env.{name}' with '{value}'")
            i = 0
            for env in obj_list[key]['spec']['template']['spec']['containers'][num]['env']:
                for item in env_list:
                    if env['name'] == item['name']:
                        obj_list[key]['spec']['template']['spec']['containers'][num]['env'][i] = item
                i += 1

    return obj_list


def enrich_deployment_calico_typha(cluster, obj_list):
    """
    The method implements the enrichment procedure for Typha Deployment
    :param cluster: Cluster object
    :param obj_list: list of objects for enrichment
    """

    default_tolerations = [{'key': 'node.kubernetes.io/network-unavailable', 'effect': 'NoSchedule'},
                           {'key': 'node.kubernetes.io/network-unavailable', 'effect': 'NoExecute'}]

    key = "Deployment_calico-typha"
    val = cluster.inventory['plugins']['calico']['typha']['replicas']
    obj_list[key]['spec']['replicas'] = int(val)
    cluster.log.verbose(f"The {key} has been patched in 'spec.replicas' with '{val}'")
    val = cluster.inventory['plugins']['calico']['typha']['nodeSelector']
    obj_list[key]['spec']['template']['spec']['nodeSelector'] = val
    cluster.log.verbose(f"The {key} has been patched in 'spec.template.spec.nodeSelector' with '{val}'")
    for val in default_tolerations:
        obj_list[key]['spec']['template']['spec']['tolerations'].append(val)
        cluster.log.verbose(f"The {key} has been patched in 'spec.template.spec.tolerations' with '{val}'")
    for val in cluster.inventory['plugins']['calico']['typha'].get('tolerations', ''):
        obj_list[key]['spec']['template']['spec']['tolerations'].append(val)
        cluster.log.verbose(f"The {key} has been patched in 'spec.template.spec.tolerations' with '{val}'")
    for container in obj_list[key]['spec']['template']['spec']['containers']:
        if container['name'] == "calico-typha":
            num = obj_list[key]['spec']['template']['spec']['containers'].index(container)
            val = enrich_image(cluster, cluster.inventory['plugins']['calico']['typha']['image'])
            obj_list[key]['spec']['template']['spec']['containers'][num]['image'] = val
            cluster.log.verbose(f"The {key} has been patched in "
                                f"'spec.template.spec.containers.[{num}].image with '{val}'")

    return obj_list


def enrich_clusterRole_calico_kube_controllers(cluster, obj_list):
    """
    The method implements the enrichment procedure for Calico controller ClusterRole
    :param cluster: Cluster object
    :param obj_list: list of objects for enrichment
    """

    key = "ClusterRole_calico-kube-controllers"
    if cluster.inventory['rbac']['admission'] == "psp" and \
            cluster.inventory['rbac']['psp']['pod-security'] == "enabled":
        api_list = obj_list[key]['rules']
        api_list.append(psp_calico_kube_controllers)
        obj_list[key]['rules'] = api_list
        cluster.log.verbose(f"The {key} has been patched in 'rules' with '{psp_calico_kube_controllers}'")

    return obj_list


def enrich_clusterrole_calico_node(cluster, obj_list):
    """
    The method implements the enrichment procedure for Calico node ClusterRole
    :param cluster: Cluster object
    :param obj_list: list of objects for enrichment
    """

    key = "ClusterRole_calico-node"
    if cluster.inventory['rbac']['admission'] == "psp" and \
            cluster.inventory['rbac']['psp']['pod-security'] == "enabled":
        api_list = obj_list[key]['rules']
        api_list.append(psp_calico_node)
        obj_list[key]['rules'] = api_list
        cluster.log.verbose(f"The {key} has been patched in 'rules' with '{psp_calico_node}'")

    return obj_list


def validate_original(cluster, obj_list):
    """
    The method implements some validations for Calico objects
    :param cluster: Cluster object
    :param obj_list: list of objects for validation
    """

    known_objects = [
        "ConfigMap_calico-config",
        "CustomResourceDefinition_bgpconfigurations.crd.projectcalico.org",
        "CustomResourceDefinition_bgppeers.crd.projectcalico.org",
        "CustomResourceDefinition_blockaffinities.crd.projectcalico.org",
        "CustomResourceDefinition_caliconodestatuses.crd.projectcalico.org",
        "CustomResourceDefinition_clusterinformations.crd.projectcalico.org",
        "CustomResourceDefinition_felixconfigurations.crd.projectcalico.org",
        "CustomResourceDefinition_globalnetworkpolicies.crd.projectcalico.org",
        "CustomResourceDefinition_globalnetworksets.crd.projectcalico.org",
        "CustomResourceDefinition_hostendpoints.crd.projectcalico.org",
        "CustomResourceDefinition_ipamblocks.crd.projectcalico.org",
        "CustomResourceDefinition_ipamconfigs.crd.projectcalico.org",
        "CustomResourceDefinition_ipamhandles.crd.projectcalico.org",
        "CustomResourceDefinition_ippools.crd.projectcalico.org",
        "CustomResourceDefinition_ipreservations.crd.projectcalico.org",
        "CustomResourceDefinition_kubecontrollersconfigurations.crd.projectcalico.org",
        "CustomResourceDefinition_networkpolicies.crd.projectcalico.org",
        "CustomResourceDefinition_networksets.crd.projectcalico.org",
        "ClusterRole_calico-kube-controllers",
        "ClusterRoleBinding_calico-kube-controllers",
        "ClusterRole_calico-node",
        "ClusterRoleBinding_calico-node",
        "DaemonSet_calico-node",
        "ServiceAccount_calico-node",
        "Deployment_calico-kube-controllers",
        "ServiceAccount_calico-kube-controllers",
        "PodDisruptionBudget_calico-kube-controllers",
        "Deployment_calico-typha",
        "Service_calico-typha", 
        "PodDisruptionBudget_calico-typha"
    ]

    # check if there are new objects
    for key in obj_list.keys():
        if key not in known_objects:
            cluster.log.verbose(f"The current version of original yaml has a new object: {key}")

    # check if known objects were excluded
    for key in known_objects:
        if key not in list(obj_list):
            cluster.log.verbose(f"The current version of original yaml does not include"
                                f"the following object: {key}")

# TODO: implement method for validation after enrichment
# Some validation inside the objects
#def validate_result(cluster, obj_list):


def load_multiple_yaml(filepath, cluster) -> dict:
    """
    The method implements the parse YAML file that includes several YAMLs inside
    :param filepath: Path to file that should be parsed
    :return: dictionary with the 'kind' and 'name' of object as 'key' and whole YAML structure as 'value'
    """
    yaml = ruamel.yaml.YAML()
    yaml_dict = {}
    try:
        with utils.open_utf8(filepath, 'r') as stream:
            source_yamls = yaml.load_all(stream)
            for source_yaml in source_yamls:
                if source_yaml:
                    yaml_key = f"{source_yaml['kind']}_{source_yaml['metadata']['name']}"
                    # check if there is no duplication
                    if not yaml_dict.get(yaml_key, ''):
                        yaml_dict[yaml_key] = source_yaml
                    else:
                        raise Exception("ERROR: the {yaml_key} object is duplicated, please verify the original yaml")
        return yaml_dict
    except Exception as exc:
        cluster.log.error(f"Failed to load {filepath}", exc)


def dump_multiple_yaml(multi_yaml: dict) -> str:
    """
    The method implements the dumping some dictionary to the string that includes several YAMLs inside
    :param multi_yaml: dictionary with the 'kind' and 'name' of object as 'key' and whole YAML structure as 'value'
    """
    yaml = ruamel.yaml.YAML()

    with io.StringIO() as stream:
        yaml.dump_all(multi_yaml.values(), stream)
        result = stream.getvalue()

    return result


def enrich_image(cluster, image):
    """
    The method adds registry to image if it's necessary
    :param cluster: Cluster object
    :param image: particular image
    """
    if cluster.inventory['plugins']['calico']['installation'].get('registry', ''):
        if len(cluster.inventory['plugins']['calico']['installation']['registry']):
            return f"{cluster.inventory['plugins']['calico']['installation']['registry']}/{image}"

    return image


# name of objects and enrichment methods mapping
enrich_objects_fns = {
        "ConfigMap_calico-config": enrich_configmap_calico_config,
        "Deployment_calico-kube-controllers": enrich_deployment_calico_kube_controllers,
        "DaemonSet_calico-node": enrich_daemonset_calico_node,
        "Deployment_calico-typha": enrich_deployment_calico_typha,
        "ClusterRole_calico-kube-controllers": enrich_clusterRole_calico_kube_controllers,
        "ClusterRole_calico-node": enrich_clusterrole_calico_node,
        "Service_calico-typha": None, 
        "PodDisruptionBudget_calico-typha": None
}

psp_calico_kube_controllers = {
        "apiGroups": ["policy"],
        "resources": ["podsecuritypolicies"],
        "verbs":     ["use"],
        "resourceNames": ["oob-anyuid-psp"]
}

psp_calico_node = {
        "apiGroups": ["policy"],
        "resources": ["podsecuritypolicies"],
        "verbs":     ["use"],
        "resourceNames": ["oob-privileged-psp"]
}
