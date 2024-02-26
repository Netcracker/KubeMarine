- [Kubemarine Patches](#kubemarine-patches)
  - [How to Write Your Own Patch](#how-to-write-your-own-patch)
  - [Software Upgrade Patches](#software-upgrade-patches)
  - [Examples](#examples)
    - [Installation Task](#installation-task)
    - [Reinstall Predefined Plugin](#reinstall-predefined-plugin)
    - [Change Default Behavior](#change-default-behavior)

# Kubemarine Patches

Patch is an automatic action that is needed to migrate a cluster managed by Kubemarine from one Kubemarine release to another.  
Patches are needed when we update Kubemarine 3rd parties, specific Kubernetes parameters, Kubemarine procedures/features, and so on.  
Patches are installed during specific [Kubemarine migration procedure](/documentation/Maintenance.md#kubemarine-migration-procedure).

## How to Write Your Own Patch

Patches are registered in a special folder [/kubemarine/patches](/kubemarine/patches).  

Every patch should inherit one of:
* `kubemarine.core.patch.InventoryOnlyPatch`
   This only changes the inventory.
   Running of enrichment is prohibited.
   Patches if this type are executed first.
* `kubemarine.core.patch.RegularPatch`. This accesses and makes some operations on the cluster.
   These patches should not upgrade software, and should not affect the upgrade procedure.
   Patches if this type are executed last.

Also see the inline pydoc in [`kubemarine.core.patch`](/kubemarine/core/patch.py).

In addition, each patch has one field and two methods to implement:
* **identifier** is a unique name of a patch that is used to recognize it and call if needed.
* **description** is a method that returns text description of a patch. This method is used in the `migrate_kubemarine --describe <patch identifier>` operation.
* **action** is a method that returns special implementation of the [`kubemarine.core.action.Action`](/kubemarine/core/action.py) class that contains the main code of a patch.

To enable a patch, you should add it to [`kubemarine.patches.__init__`](/kubemarine/patches/__init__.py#L26).
Patches that have the same type are executed in the order that is declared there.

## Software Upgrade Patches

There is one more type of patches that upgrades different types of software.
Such patches are executed after patches of the type `InventoryOnlyPatch` and before patches of the type `RegularPatch`,
and are registered automatically as long as the [`kubemarine/patches/software_upgrade.yaml`](/kubemarine/patches/software_upgrade.yaml) configuration is changed.

For more information, refer to the [design document](/documentation/design/1-upgrade-patches-registration-and-implementation.md).

## Examples

All historical patches can be viewed using the command:
```shell
git log --oneline -- kubemarine/patches | grep -v "Delete all patches after release"
```

Below are the actual templates for `InventoryOnlyPatch` and `RegularPatch` patches.
Also see the inline comments.
<details>
  <summary>Inventory only patch</summary>
<pre>
from textwrap import dedent<br>
from kubemarine.core.action import Action
from kubemarine.core.patch import InventoryOnlyPatch
from kubemarine.core.resources import DynamicResources<br><br>
class TheAction(Action):
    def __init__(self) -> None:
        super().__init__("&lt;Short description of action&gt;")<br>
    def run(self, res: DynamicResources) -> None:
        inventory = res.formatted_inventory()<br>
        # patch_is_applicable(), do_some_changes_in_inventory() are some methods for you to implement.
        # You may also follow the different ways:
        # 1) always recreate the inventory even if there are no real changes;
        # 2) set `self.recreate_inventory = True` on-the-fly while modifying of the inventory;
        # 3) other.
        if patch_is_applicable(inventory):
            self.recreate_inventory = True
            do_some_changes_in_inventory(inventory)
        else:
            res.logger().info("Nothing has changed")<br>
        # Calling of the below method is prohibited!
        # cluster = res.cluster()<br><br>
class MyPatch(InventoryOnlyPatch):
    def __init__(self) -> None:
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
    def __init__(self) -> None:
        super().__init__("&lt;Short description of action&gt;")<br>
    def run(self, res: DynamicResources) -> None:
        cluster = res.cluster()<br>
        # patch_is_applicable(), do_some_changes_on_cluster() are some methods for you to implement.
        if patch_is_applicable(cluster):
            do_some_changes_on_cluster(cluster)
        else:
            cluster.log.info("Nothing has changed")<br><br>
class MyPatch(RegularPatch):
    def __init__(self) -> None:
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

As you can see, the main code is located in custom implementation of `Action.run()`.
The following examples illustrate how to implement it in some common situations.

### Installation Task

In some cases applying of a patch can be effectively equal to running of some [installation task](../Installation.md#installation-tasks-description).
For example, it can be possible to apply changes in the configuration of HAProxy by simple `kubemarine install --tasks deploy.loadbalancer.haproxy.configure`.
To do the same through a patch, use the following:

```python
from kubemarine.core.action import Action
from kubemarine.core.cluster import KubernetesCluster
from kubemarine.core.resources import DynamicResources
from kubemarine.procedures import install


class TheAction(Action):
    def run(self, res: DynamicResources) -> None:
        cluster = res.cluster()
        if self.is_applicable(cluster):
            install.run_tasks(res, ['deploy.loadbalancer.haproxy.configure'])
        else:
            cluster.log.info("Nothing has changed")

    def is_applicable(self, cluster: KubernetesCluster): ...
```

### Reinstall Predefined Plugin

If it is necessary to re-install some [predefined plugin](../Installation.md#predefined-plugins), use the following:

```python
from kubemarine import plugins
from kubemarine.core.action import Action
from kubemarine.core.cluster import KubernetesCluster
from kubemarine.core.resources import DynamicResources


class TheAction(Action):
    def run(self, res: DynamicResources) -> None:
        cluster = res.cluster()
        if self.is_applicable(cluster):
            # the following example if for `calico`
            plugins.install(cluster, {'calico': cluster.inventory['plugins']['calico']})
        else:
            cluster.log.info("Nothing has changed")

    def is_applicable(self, cluster: KubernetesCluster): ...
```

### Change Default Behavior

Sometimes we need to change the default configuration of some services like [defaults.yaml](/kubemarine/resources/configurations/defaults.yaml)
or to change the default behavior of Kubemarine.
Although the new version of Kubemarine follows better practices, it is possible to persist the old behavior for old clusters.

If the old behavior remains configurable, we can set it in the patch.

```python
from kubemarine.core.action import Action
from kubemarine.core.resources import DynamicResources


class TheAction(Action):
    def __init__(self) -> None:
        # note `recreate_inventory=True`
        super().__init__("Ensure backward compatibility", recreate_inventory=True)
    
    def run(self, res: DynamicResources) -> None:
        res.formatted_inventory()['property_that_sets_previous_default_behaviour'] = True
```
