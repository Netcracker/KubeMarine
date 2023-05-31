# Kubemarine patches

Patch is an automatic action, that is needed to migrate the cluster, that is managed by Kubemarine, from one Kubemarine release to another.  
Patches are needed when we update Kubemarine 3rd parties, specific kubernetes parameters, Kubemarine procedures/features, etc.  
Patches are installed during specific [Kubemarine migration procedure](/documentation/Maintenance.md#kubemarine-migration-procedure).

## How to write your own patch

Patches are registered in a special folder [/kubemarine/patches](/kubemarine/patches).  

Every patch should inherit one of:
* `kubemarine.core.patch.InventoryOnlyPatch`.
   Only changes the inventory.
   Running of enrichment is prohibited.
   Patches if this type are executed first.
* `kubemarine.core.patch.RegularPatch`. Accesses and makes some operations on the cluster.
   These patches should not upgrade software, and should not affect the upgrade procedure.
   Patches if this type are executed last.

See also inline pydoc in [`kubemarine.core.patch`](/kubemarine/core/patch.py).

In addition, each patch has one field and two methods to implement:
* **identifier** is a unique name of patch, that is used to recognize it and call if needed;
* **description** is a method that returns text description of the patch. This method is used in `migrate_kubemarine --describe <patch identifier>` operation;
* **action** is a method that returns special implementation of [`kubemarine.core.action.Action`](/kubemarine/core/action.py) class that contains main code of patch.

To enable the patch, you should add it to the [`kubemarine.patches.__init__`](/kubemarine/patches/__init__.py#L26).
Patches that have the same type, are executed in the order that is declared there.

## Software upgrade patches

There is one more type of patches that upgrade different types of software.
Such patches are executed after patches of type `InventoryOnlyPatch` and before patches of type `RegularPatch`,
and are registered automatically as long as the [`kubemarine/patches/software_upgrade.yaml`](/kubemarine/patches/software_upgrade.yaml) configuration is changed.

See also the [design document](/documentation/design/1-upgrade-patches-registration-and-implementation.md).

## Example

<details>
  <summary>Inventory only patch</summary>
<pre>
from textwrap import dedent<br>
from kubemarine.core.action import Action
from kubemarine.core.patch import InventoryOnlyPatch
from kubemarine.core.resources import DynamicResources<br><br>
class TheAction(Action):
    def __init__(self):
        super().__init__("&lt;Short description of action&gt;")<br>
    def run(self, res: DynamicResources):
        inventory = res.formatted_inventory()
        do_some_changes_in_inventory(inventory)
        # Calling of the below method is prohibited!
        # cluster = res.cluster()<br><br>
class MyPatch(InventoryOnlyPatch):
    def __init__(self):
        super().__init__("&lt;patch_id&gt;")<br>
    @property
    def action(self) -> Action:
        return TheAction()<br>
    @property
    def description(self) -> str:
        return dedent(
            f"""\
            &lt;Comprehensive 
            multiline
            description of the patch&gt;
            """.rstrip()
        )
</pre>
</details>

<details>
  <summary>Regular patch</summary>
<pre>
from textwrap import dedent<br>
from kubemarine.core.action import Action
from kubemarine.core.patch import RegularPatch
from kubemarine.core.resources import DynamicResources<br><br>
class TheAction(Action):
    def __init__(self):
        super().__init__("&lt;Short description of action&gt;")<br>
    def run(self, res: DynamicResources):
        cluster = res.cluster()
        do_some_changes_on_cluster(cluster)<br><br>
class MyPatch(RegularPatch):
    def __init__(self):
        super().__init__("&lt;patch_id&gt;")<br>
    @property
    def action(self) -> Action:
        return TheAction()<br>
    @property
    def description(self) -> str:
        return dedent(
            f"""\
            &lt;Comprehensive 
            multiline
            description of the patch&gt;
            """.rstrip()
        )
</pre>
</details>
