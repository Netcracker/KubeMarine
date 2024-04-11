from textwrap import dedent

import yaml

from kubemarine.core.action import Action
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


class TheAction(Action):
    def __init__(self) -> None:
        super().__init__("Set previous default kernel parameters", recreate_inventory=True)

    def run(self, res: DynamicResources) -> None:
        inventory = res.inventory()

        defaults = yaml.safe_load(OLD_SYSCTL_DEFAULTS)
        sysctl_config = inventory.setdefault('services', {}).setdefault('sysctl', {})
        for k, v in defaults.items():
            if k not in sysctl_config:
                sysctl_config[k] = v


class PreserveCompatibilitySysctl(InventoryOnlyPatch):
    def __init__(self) -> None:
        super().__init__("preserve_compatibility_sysctl")

    @property
    def action(self) -> Action:
        return TheAction()

    @property
    def description(self) -> str:
        return dedent(
            f"""\
            Set previous default kernel parameters in the user inventory.
            
            This allows to preserve dynamic references to the default parameters in jinja templates.
            """.rstrip()
        )
