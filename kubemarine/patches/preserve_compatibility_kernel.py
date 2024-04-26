# Copyright 2021-2023 NetCracker Technology Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from textwrap import dedent

import yaml

from kubemarine import packages
from kubemarine.core import yaml_merger, errors
from kubemarine.core.action import Action
from kubemarine.core.cluster import EnrichmentStage
from kubemarine.core.patch import InventoryOnlyPatch
from kubemarine.core.resources import DynamicResources

OLD_SYSCTL_DEFAULTS = """
    net.bridge.bridge-nf-call-iptables: 1
    net.ipv4.ip_forward: 1
    net.ipv4.ip_nonlocal_bind: 1
    net.ipv4.conf.all.route_localnet: 1
    net.bridge.bridge-nf-call-ip6tables: '{% if not nodes[0]["internal_address"]|isipv4 %}1{% endif %}'
    net.ipv6.conf.all.forwarding: '{% if not nodes[0]["internal_address"]|isipv4 %}1{% endif %}'
    net.ipv6.ip_nonlocal_bind: '{% if not nodes[0]["internal_address"]|isipv4 %}1{% endif %}'
    net.netfilter.nf_conntrack_max: 1000000
    kernel.panic: 10
    vm.overcommit_memory: 1
    kernel.panic_on_oops: 1
"""

OLD_MODPROBE_DEFAULTS = """
    rhel:
      - br_netfilter
      - '{% if not nodes[0]["internal_address"]|isipv4 %}nf_conntrack_ipv6{% else %}nf_conntrack{% endif %}'
      - '{% if not nodes[0]["internal_address"]|isipv4 %}ip6table_filter{% endif %}'
      - '{% if not nodes[0]["internal_address"]|isipv4 %}nf_nat_masquerade_ipv6{% endif %}'
      - '{% if not nodes[0]["internal_address"]|isipv4 %}nf_reject_ipv6{% endif %}'
      - '{% if not nodes[0]["internal_address"]|isipv4 %}nf_defrag_ipv6{% endif %}'
    rhel8:
      - br_netfilter
      - nf_conntrack
      - '{% if not nodes[0]["internal_address"]|isipv4 %}ip6table_filter{% endif %}'
      - '{% if not nodes[0]["internal_address"]|isipv4 %}nf_nat{% endif %}'
      - '{% if not nodes[0]["internal_address"]|isipv4 %}nf_reject_ipv6{% endif %}'
      - '{% if not nodes[0]["internal_address"]|isipv4 %}nf_defrag_ipv6{% endif %}'
    rhel9:
      - br_netfilter
      - nf_conntrack
      - '{% if not nodes[0]["internal_address"]|isipv4 %}ip6table_filter{% endif %}'
      - '{% if not nodes[0]["internal_address"]|isipv4 %}nf_nat{% endif %}'
      - '{% if not nodes[0]["internal_address"]|isipv4 %}nf_reject_ipv6{% endif %}'
      - '{% if not nodes[0]["internal_address"]|isipv4 %}nf_defrag_ipv6{% endif %}'
    debian:
      - br_netfilter
      - nf_conntrack
      - '{% if not nodes[0]["internal_address"]|isipv4 %}ip6table_filter{% endif %}'
      - '{% if not nodes[0]["internal_address"]|isipv4 %}nf_nat{% endif %}'
      - '{% if not nodes[0]["internal_address"]|isipv4 %}nf_reject_ipv6{% endif %}'
      - '{% if not nodes[0]["internal_address"]|isipv4 %}nf_defrag_ipv6{% endif %}'
"""


class TheAction(Action):
    def __init__(self) -> None:
        super().__init__("Set previous default kernel parameters and modules", recreate_inventory=True)

    def run(self, res: DynamicResources) -> None:
        inventory = res.inventory()
        os_family = res.cluster(EnrichmentStage.LIGHT).get_os_family()
        if os_family not in packages.get_associations_os_family_keys():
            raise errors.KME("KME0012", procedure='migrate_kubemarine')

        sysctl_defaults = yaml.safe_load(OLD_SYSCTL_DEFAULTS)
        sysctl_config = inventory.setdefault('services', {}).setdefault('sysctl', {})
        for k, v in sysctl_defaults.items():
            if k not in sysctl_config:
                sysctl_config[k] = v

        default_list = yaml.safe_load(OLD_MODPROBE_DEFAULTS)[os_family]
        modprobe_config = inventory.setdefault('services', {}).setdefault('modprobe', {})
        if os_family not in modprobe_config:
            modprobe_config[os_family] = default_list
        else:
            modules_list = modprobe_config[os_family]
            strategy, pos = yaml_merger.get_strategy_position(modules_list, ['services', 'modprobe', os_family])
            if strategy == 'merge':
                modules_list[pos:(pos+1)] = default_list


class PreserveCompatibilityKernel(InventoryOnlyPatch):
    def __init__(self) -> None:
        super().__init__("preserve_compatibility_kernel")

    @property
    def action(self) -> Action:
        return TheAction()

    @property
    def description(self) -> str:
        return dedent(
            f"""\
            Set previous default kernel parameters and modules in the user inventory.
            
            This keeps as-is all parameters and modules previously installed by Kubemarine.
            This also preserves dynamic references to the default kernel parameters in jinja templates.
            """.rstrip()
        )
