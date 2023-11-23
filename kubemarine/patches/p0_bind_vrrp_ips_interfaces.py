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
from typing import Optional

from kubemarine.core.action import Action
from kubemarine.core.patch import RegularPatch
from kubemarine.core.resources import DynamicResources


class TheAction(Action):
    def __init__(self) -> None:
        super().__init__("Set previously resolved interfaces for VRRP IPs")

    def run(self, res: DynamicResources) -> None:
        logger = res.logger()
        cluster = res.cluster()

        if cluster.make_group_from_roles(['keepalived']).is_empty():
            return logger.info("Skipping the patch as Keepalived is not configured.")

        first_resolved_interface: Optional[str] = None
        for i, raw_item in enumerate(cluster.raw_inventory['vrrp_ips']):
            # If hosts are not specified, they are resolved by new algorithm.
            if isinstance(raw_item, str) or 'hosts' not in raw_item:
                item = cluster.inventory['vrrp_ips'][i]
                # There is at least one balancer that produced at least one host for VRRP IP
                resolved_interface = item['hosts'][0]['interface']
                if first_resolved_interface is None:
                    first_resolved_interface = resolved_interface
                    continue

                # The further VRRP IPs without hosts previously was enriched with 'first_resolved_interface'
                # Let's compare it with how it is resolved now.
                if resolved_interface != first_resolved_interface:
                    logger.info(f"Changing vrrp_ips[{i}].interface to {first_resolved_interface} "
                                f"to preserve the backward compatibility.")
                    formatted_item = res.formatted_inventory()['vrrp_ips'][i]
                    if isinstance(raw_item, str):
                        res.formatted_inventory()['vrrp_ips'][i] = formatted_item = {
                            'ip': formatted_item
                        }

                    formatted_item['interface'] = first_resolved_interface
                    item['interface'] = first_resolved_interface
                    for record in item['hosts']:
                        record['interface'] = first_resolved_interface

                    self.recreate_inventory = True

        if not self.recreate_inventory:
            logger.info("Skipping the patch as interfaces for `vrrp_ips` were not changed.")


class FixVRRP_IPsInterfaces(RegularPatch):
    def __init__(self) -> None:
        super().__init__("fix_vrrp_ips_interfaces")

    @property
    def action(self) -> Action:
        return TheAction()

    @property
    def description(self) -> str:
        return dedent(
            f"""\
            The patch sets previously resolved interfaces for the VRRP IPs
            in the inventory to preserve the backward compatibility.
            """.rstrip()
        )
