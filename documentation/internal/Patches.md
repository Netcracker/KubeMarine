# Kubemarine patches

Patch is automatic action, what is needed to migrate cluster, that is managed via kubemarine, from one kubemarine release to another.  
Patches are needed when weupdate kubetools 3rd parties, specific kubernetes parameters, kubetools procudures/features and etc.  
Patches are installed during specific kubemarine migration procedure. Information about it can be found in [migration procedure guide](/documentation/Maintenance.md#kubemarine-migration-procedure).

## How to write your own patch

Patches are described in special [folder](/kubemarine/patches).  

Every patch is an inheritor of [abstract Patch class](/kubemarine/core/patch.py) that has one field and two methods to implement:
* **identifier** is unique name of patch, that is used to reqognize it and call if needed;
* **description** is method that returns text description of patch. This method is used in `migrate_kubemarine --describe patch` operation;
* **action** is method that returns special implementation of [abstract Action](/kubemarine/core/action.py) class there code of patch is placed.

To enable patch you should add this patch to [special list](/kubemarine/patches/__init__.py#L26). The order of patches there are correspond with the patch  execution order.

## Example

Example of patch you can find in [kubemarine release 0.4.0](https://github.com/Netcracker/KubeMarine/tree/0.4.0/kubemarine/patches).