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

from kubemarine.core.group import NodeGroupResult
from kubemarine.cri import docker, containerd


def enrich_inventory(inventory, cluster):
    if "docker" in cluster.inventory['services']:
        raise Exception(f"docker configuration no longer belongs to 'services.docker' section, "
                        f"please move docker configuration to 'services.cri.dockerConfig' section")

    cri_impl = inventory['services']['cri']['containerRuntime']
    if cri_impl != "docker" and cri_impl != "containerd":
        raise Exception("Unexpected container runtime specified: %s, supported are: docker, containerd" % cri_impl)

    if cluster.context.get("initial_procedure") == "migrate_cri":
        return inventory

    if cri_impl == "docker":
        forbidden_cri_sections = {"containerd": "containerdConfig"}
    else:
        forbidden_cri_sections = {"docker": "dockerConfig"}
    for key, value in forbidden_cri_sections.items():
        if value in cluster.raw_inventory.get('services', {}).get('cri', {}):
            raise Exception(f"{key} is not used, please remove {value} config from `services.cri` section")

    return inventory


def install(group):
    cri_impl = group.cluster.inventory['services']['cri']['containerRuntime']

    if cri_impl == "docker":
        return docker.install(group)
    else:
        return containerd.install(group)


def configure(group):
    cri_impl = group.cluster.inventory['services']['cri']['containerRuntime']

    if cri_impl == "docker":
        return docker.configure(group)
    else:
        return containerd.configure(group)


def prune(group, all_implementations=False):
    cri_impl = group.cluster.inventory['services']['cri']['containerRuntime']

    result = NodeGroupResult(group.cluster)
    if cri_impl == "docker" or all_implementations:
        result.update(docker.prune(group))

    if cri_impl == "containerd" or all_implementations:
        result.update(containerd.prune(group))

    return result
