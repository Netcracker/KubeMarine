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

import yaml
import ipaddress

from copy import deepcopy

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

    return inventory


def enrich_original_yaml(cluster):
    items = cluster.inventory['plugins']['calico']['installation']['procedures']
    for item in items:
        if item.get('config', ''):
            calico_original_yaml = f"{item['config']['source']}.original"
            calico_yaml = item['config']['source']
    cluster.log.debug(f"ORIGINAL: {calico_original_yaml}") 
    cluster.log.debug(f"PATCHED: {calico_yaml}")
    obj_list = utils.load_multiple_yaml(calico_original_yaml)

    for key in list(obj_list):

        if key == "ConfigMap_calico-config":
            obj_list[key]['data']['veth_mtu'] = str(cluster.inventory['plugins']['calico']['mtu'])
            if cluster.inventory['plugins']['calico']['typha']['enabled'] == True:
                obj_list[key]['data']['typha_service_name'] = 'calico-typha'
            else:
                obj_list[key]['data']['typha_service_name'] = 'none'
            string_part = obj_list[key]['data']['cni_network_config']
            yaml_part = yaml.safe_load(string_part.replace('\n', '').replace('\\', ''))
            ip = cluster.inventory['services']['kubeadm']['networking']['podSubnet'].split('/')[0]
            if type(ipaddress.ip_address(ip)) is ipaddress.IPv4Address:
                yaml_part['plugins'][0]['ipam'] = cluster.inventory['plugins']['calico']['cni']['ipam']['ipv4']
            else:
                yaml_part['plugins'][0]['ipam'] = cluster.inventory['plugins']['calico']['cni']['ipam']['ipv6']
            obj_list[key]['data']['cni_network_config'] = str(yaml_part).replace("'__CNI_MTU__'", "__CNI_MTU__").replace("'","\"")

        if key == "Deployment_calico-kube-controllers":
            obj_list[key]['spec']['template']['spec']['nodeSelector'] = \
                    cluster.inventory['plugins']['calico']['kube-controllers']['nodeSelector']
            for container in obj_list[key]['spec']['template']['spec']['containers']:
                if container['name'] == "calico-kube-controllers":
                    num = obj_list[key]['spec']['template']['spec']['containers'].index(container)
                    obj_list[key]['spec']['template']['spec']['containers'][num]['image'] = \
                            f"{cluster.inventory['plugins']['calico']['kube-controllers']['image']}"

        if key == "DaemonSet_calico-node":
            for container in obj_list[key]['spec']['template']['spec']['initContainers']:
                if container['name'] in ['upgrade-ipam', 'install-cni']: 
                    num = obj_list[key]['spec']['template']['spec']['initContainers'].index(container)
                    obj_list[key]['spec']['template']['spec']['initContainers'][num]['image'] = \
                            f"{cluster.inventory['plugins']['calico']['cni']['image']}"
                if container['name'] == "mount-bpffs":
                    num = obj_list[key]['spec']['template']['spec']['initContainers'].index(container)
                    obj_list[key]['spec']['template']['spec']['initContainers'][num]['image'] = \
                            f"{cluster.inventory['plugins']['calico']['node']['image']}"
            for container in obj_list[key]['spec']['template']['spec']['containers']:
                if container['name'] == "calico-node":
                    num = obj_list[key]['spec']['template']['spec']['containers'].index(container)
                    cluster.log.debug(f"ENV_ORIGINAL: {obj_list[key]['spec']['template']['spec']['containers'][num]['env']}")
                    obj_list[key]['spec']['template']['spec']['containers'][num]['image'] = \
                            f"{cluster.inventory['plugins']['calico']['node']['image']}"
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
                        elif name in ipv6_env and type(ipaddress.ip_address(ip)) is not ipaddress.IPv4Address:
                            if type(value) is str:
                                env_list.append({'name': name, 'value': value})
                            elif type(value) is dict:
                                env_list.append({'name': name, 'valueFrom': value})
                        if cluster.inventory['plugins']['calico']['typha']['enabled'] and \
                                name == 'FELIX_TYPHAK8SSERVICENAME':
                                env_list.append({'name': name, 'valueFrom': value})
                        cluster.log.debug(f"NAME: {name}, VALUE: {value}")
                    cluster.log.debug(f"ENV: {env_list}")
                    obj_list[key]['spec']['template']['spec']['containers'][num]['env'] = env_list

        if key in ["Service_calico-typha", "PodDisruptionBudget_calico-typha"]:
            if not cluster.inventory['plugins']['calico']['typha']['enabled']:
                obj_list.pop(key)

        if key == "Deployment_calico-typha":
            if not cluster.inventory['plugins']['calico']['typha']['enabled']:
                obj_list.pop(key)
            else:
                obj_list[key]['spec']['replicas'] = cluster.inventory['plugins']['calico']['typha']['replicas']
                obj_list[key]['spec']['template']['spec']['nodeSelector'] = \
                        cluster.inventory['plugins']['calico']['typha']['nodeSelector']
                if container['name'] == "calico-typha":
                    num = obj_list[key]['spec']['template']['spec']['containers'].index(container)
                    obj_list[key]['spec']['template']['spec']['containers'][num]['image'] = \
                            f"{cluster.inventory['plugins']['calico']['typha']['image']}"

    utils.save_multiple_yaml(calico_yaml, obj_list)
