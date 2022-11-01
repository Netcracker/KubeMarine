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

def enrich_original_yaml(inventory, cluster, original_yaml):
    for key in obj_list:
        if key == "ConfigMap_calico-config":
            ls['ConfigMap_calico-config']['data']['veth_mtu'] = str(cluster['plugins']['calico']['mtu'])
            if cluster['plugins']['calico']['typha']['enabled'] == True:
                ls['ConfigMap_calico-config']['data']['typha_service_name'] = 'calico-typha'
            else:
                ls['ConfigMap_calico-config']['data']['typha_service_name'] = 'none'
            string_part = ls['ConfigMap_calico-config']['data']['cni_network_config']
            yaml_part = yaml.safe_load(string_part.replace('\n', '').replace('\\', ''))
            ip = cluster['services']['kubeadm']['networking']['podSubnet'].split('/')[0]
            if type(ipaddress.ip_address(ip)) is ipaddress.IPv4Address:
                yaml_part['plugins'][0]['ipam'] = cluster['plugins']['calico']['cni']['ipam']['ipv4']
            else:
                yaml_part['plugins'][0]['ipam'] = cluster['plugins']['calico']['cni']['ipam']['ipv6']
            ls['ConfigMap_calico-config']['data']['cni_network_config'] = str(yaml_part).replace("'__CNI_MTU__'", "__CNI_MTU__").replace("'","\"")

    return patched_yaml
