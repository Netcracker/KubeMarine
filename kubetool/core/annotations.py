from kubetool.core.group import NodeGroup


def restrict_multi_os_group(fn: callable):
    """
    Method is an annotation that does not allow origin method to use different OS families in the same group.
    :param fn: Origin function to apply annotation validation to
    :return: Validation wrapper function
    """
    def wrapper(group: NodeGroup, *args, **kwargs):
        # TODO: walk through all nodes in *args, check isinstance NodeGroup and perform validation
        if group.is_multi_os():
            raise Exception(f'Method "{str(fn)}" do not supports multi-os group')
        return fn(group, *args, **kwargs)
    return wrapper
