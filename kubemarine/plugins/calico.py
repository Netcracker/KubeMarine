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

import ipaddress
import ruamel.yaml

from copy import deepcopy

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

    return inventory


def enrich_original_yaml(cluster):
    # get original YAML and parse it into dict of objects
    items = cluster.inventory['plugins']['calico']['installation']['procedures']
    for item in items:
        if item.get('config', ''):
            calico_original_yaml = f"{item['config']['source']}.original"
            calico_yaml = item['config']['source']
    obj_list = load_multiple_yaml(calico_original_yaml)

    validate_original(cluster, obj_list)

    patched_list = []
    excluded_list = []

    # patch the objects one by one
    key = "ConfigMap_calico-config"
    if obj_list.get(key, ''):
        patched_list.append(key)
        val = cluster.inventory['plugins']['calico']['mtu']
        obj_list[key]['data']['veth_mtu'] = str(val)
        cluster.log.verbose(f"The {key} has been patched in 'data.typha_service_name' with '{val}'")
        if cluster.inventory['plugins']['calico']['typha']['enabled'] == True:
            val = "calico-typha"
        else:
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

    key = "Deployment_calico-kube-controllers"
    if obj_list.get(key, ''):
        patched_list.append(key)
        obj_list[key]['spec']['template']['spec']['nodeSelector'] = \
                cluster.inventory['plugins']['calico']['kube-controllers']['nodeSelector']
        for container in obj_list[key]['spec']['template']['spec']['containers']:
            if container['name'] == "calico-kube-controllers":
                num = obj_list[key]['spec']['template']['spec']['containers'].index(container)
                val = f"{cluster.inventory['plugins']['calico']['kube-controllers']['image']}"
                obj_list[key]['spec']['template']['spec']['containers'][num]['image'] = val
                cluster.log.verbose(f"The {key} has been patched in "
                                    f"'spec.template.spec.containers.[{num}].image with '{val}'")

    key = "DaemonSet_calico-node"
    if obj_list.get(key, ''):
        patched_list.append(key)
        for container in obj_list[key]['spec']['template']['spec']['initContainers']:
            if container['name'] in ['upgrade-ipam', 'install-cni']: 
                num = obj_list[key]['spec']['template']['spec']['initContainers'].index(container)
                val = f"{cluster.inventory['plugins']['calico']['cni']['image']}"
                obj_list[key]['spec']['template']['spec']['initContainers'][num]['image'] = val
                cluster.log.verbose(f"The {key} has been patched in "
                                    f"'spec.template.spec.initContainers.[{num}].image' with '{val}'")
            if container['name'] == "mount-bpffs":
                num = obj_list[key]['spec']['template']['spec']['initContainers'].index(container)
                val = f"{cluster.inventory['plugins']['calico']['node']['image']}"
                obj_list[key]['spec']['template']['spec']['initContainers'][num]['image'] = val
                cluster.log.verbose(f"The {key} has been patched in "
                                    f"'spec.template.spec.initContainers.[{num}].image' with '{val}'")
            if container['name'] == "flexvol-driver":
                num = obj_list[key]['spec']['template']['spec']['initContainers'].index(container)
                val = f"{cluster.inventory['plugins']['calico']['flexvol']['image']}"
                obj_list[key]['spec']['template']['spec']['initContainers'][num]['image'] = val
                cluster.log.verbose(f"The {key} has been patched in "
                                    f"'spec.template.spec.initContainers.[{num}].image' with '{val}'")
        for container in obj_list[key]['spec']['template']['spec']['containers']:
            if container['name'] == "calico-node":
                num = obj_list[key]['spec']['template']['spec']['containers'].index(container)
                val = f"{cluster.inventory['plugins']['calico']['node']['image']}"
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
                    if cluster.inventory['plugins']['calico']['typha']['enabled'] and \
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

    for key in ["Service_calico-typha", "PodDisruptionBudget_calico-typha"]:
        if obj_list.get(key, ''):
            if not cluster.inventory['plugins']['calico']['typha']['enabled']:
                obj_list.pop(key)
                excluded_list.append(key)
                cluster.log.verbose(f"The {key} has been excluded")
            else:
                patched_list.append(key)

    key = "Deployment_calico-typha"
    if obj_list.get(key, ''):
        if not cluster.inventory['plugins']['calico']['typha']['enabled']:
            obj_list.pop(key)
            excluded_list.append(key)
            cluster.log.verbose(f"The {key} has been excluded")
        else:
            patched_list.append(key)
            val = cluster.inventory['plugins']['calico']['typha']['replicas']
            obj_list[key]['spec']['replicas'] = val
            cluster.log.verbose(f"The {key} has been patched in 'spec.replicas' with '{val}'")
            val = cluster.inventory['plugins']['calico']['typha']['nodeSelector']
            obj_list[key]['spec']['template']['spec']['nodeSelector'] = val
            cluster.log.verbose(f"The {key} has been patched in 'spec.template.spec.nodeSelector' with '{val}'")
            if container['name'] == "calico-typha":
                num = obj_list[key]['spec']['template']['spec']['containers'].index(container)
                val = f"{cluster.inventory['plugins']['calico']['typha']['image']}"
                obj_list[key]['spec']['template']['spec']['containers'][num]['image'] = val
                cluster.log.verbose(f"The {key} has been patched in "
                                    f"'spec.template.spec.containers.[{num}].image with '{val}'")

    cluster.log.verbose(f"The total number of patched objects is {len(patched_list)} "
                        f"the objects are the following: {patched_list}")
    cluster.log.verbose(f"The total number of exclued objects is {len(excluded_list)} "
                        f"the objects are the following: {excluded_list}")

    # TODO: check results 
    #validate_result()
    save_multiple_yaml(calico_yaml, obj_list)


def validate_original(cluster, obj_list):

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
        "PodDisruptionBudget_calico-kube-controllers"        
    ]

    # check if there are new objects
    for key, _ in obj_list.items():
        if key not in known_objects:
            cluster.log.verbose(f"The current version of original yaml has a new object: {key}")

    # check if known objects were excluded
    for key in known_objects:
        if key not in list(obj_list):
            cluster.log.verbose(f"The current version of original yaml does not include"
                                f"the following object: {key}")

# TODO: implement method for results validation
# 'mount-bpffs' and 'flexvol-driver' initContainers must not be at the same result YAML, result validation should cover this case
# Some validation inside the objects
#def validate_result(cluster, obj_list):


def load_multiple_yaml(filepath) -> dict:
    yaml = ruamel.yaml.YAML()
    yaml_dict = {}
    try:
        with open(filepath, 'r') as stream:
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
        print(f"Failed to load {filepath}", exc)


def save_multiple_yaml(filepath, multi_yaml) -> None:
    yaml = ruamel.yaml.YAML()
    source_yamls = []
    try:
        with open(filepath, 'w') as stream:
            for item in multi_yaml:
                source_yamls.append(deepcopy(multi_yaml[item]))
            yaml.dump_all(source_yamls, stream)
    except Exception as exc:
        print(f"Failed to save {filepath}", exc)
