import yaml
import jinja2

from kubetool.core import defaults


def new(log, root=None):
    if root is None:
        root = {}
    env = jinja2.Environment()
    env.filters['toyaml'] = lambda data: yaml.dump(data, default_flow_style=False)
    env.filters['isipv4'] = lambda ip: ":" not in precompile(log, ip, root)
    env.filters['minorversion'] = lambda version: ".".join(precompile(log, version, root).split('.')[0:2])
    env.filters['majorversion'] = lambda version: precompile(log, version, root).split('.')[0]

    return env


def precompile(log, struct, root):
    # maybe we have non compiled string like templates/plugins/calico-{{ globals.compatibility_map }} ?
    if '{{' in struct or '{%' in struct:
        struct = defaults.compile_object(log, struct, root)
    return struct
