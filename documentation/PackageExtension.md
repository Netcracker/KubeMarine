This section describes the ways in which to extend the standard functionality of the package with new features.

- [Basic Overview](#basic-overview)
  - [Package Structure](#package-structure)
- [Extension API](#extension-api)
  - [Class Extension](#class-extension)
  - [Launcher Extension](#launcher-extension)

## Basic Overview

All available code is formed in a single python package `kubemarine`. You can call and modify any modules, variables,
classes and methods from this package in runtime. 

For example, create new Kubernetes cluster and execute whoami on all nodes with the following code:

```python
#!/usr/bin/env python3

from kubemarine.core.resources import DynamicResources
from kubemarine.core import flow


def main():
    context = flow.create_empty_context(args={
        'config': 'cluster.yaml',
        'dump_location': './dump/'
    }, procedure='install')
    resources = DynamicResources(context)
    results = resources.cluster().nodes['control-plane'].sudo('whoami')
    print(results)


if __name__ == '__main__':
    main()
```

It is not necessary to modify the existing behavior of the Kubemarine - you can write your solution on top of this
package by calling our classes and methods under the hood. However, if you need to add new procedures, change
configuration paths or inject new methods, read the next [Extension API](#extension-api) section.

**Note**: any interference with the work of the package is completely your responsibility and we will not provide you
support if something does not work as intended to work out of the box.

### Package Structure

The package is structured as follows:

- **kubemarine** - general directory, where all subpackages and main modules are located
  - **core** - package engine, the modules of which organize the work of all
  - **procedures** - contains all available procedures that describe the sequence of actions
  - **templates** - stores a set of all jinja templates of configurations
  - **resources** - generic files required for source code
    - **configurations** - set of main configuration files, on the basis of which all package operation is built
    - **drop_ins** - configuration files uploaded unchanged
    - **reports** - checker reports related stuff
    - **scripts** - build-in bash scripts for procedures
  - **cri** - contains modules for working with container runtime interfaces

## Extension API

### Class Extension

If you need to make changes inside of the class, for example, add new methods, change existing ones or change constant
variables, then you can extend the existing classes by inheriting from them. The example further allows you to change
the path of the global config in the class:

```python
#!/usr/bin/env python3

from kubemarine.core.cluster import KubernetesCluster


class MySuperCluster(KubernetesCluster):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.GLOBALS_YAML_LOC = "/tmp/modified/custom_globals.yaml"
        self._load()
```


### Launcher Extension

If you want to use the original Kubemarine Launcher with all its built-in features, you can modify that too. The example
further allows you to replace the native class of the cluster, as well as add an additional procedure to the list of
original ones.

```python
#!/usr/bin/env python3

from kubemarine.core import flow
from kubemarine import __main__

flow.DEFAULT_CLUSTER_OBJ = MySuperCluster

__main__.procedures['foo'] = {
    'description': 'Custom procedure',
    'group': 'checks',
    'executable': 'my_custom_package.procedures.foo'
}

__main__.main()
```
