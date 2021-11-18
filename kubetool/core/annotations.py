from kubetool.core.group import NodeGroup


def restrict_multi_os_group(fn):
    def wrapper(group: NodeGroup, *args, **kwargs):
        if group.is_multi_os():
            raise Exception('Method do not supports multi-os group')
        return fn(group, *args, **kwargs)
    return wrapper
