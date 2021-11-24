import io

from kubetool.core.group import NodeGroupResult

DEBIAN_HEADERS = 'DEBIAN_FRONTEND=noninteractive '


def ls_repofiles(group, **kwargs) -> NodeGroupResult:
    return group.sudo('ls -la /etc/apt/sources.list.d', **kwargs)


def backup_repo(group, repo_filename="*", **kwargs) -> NodeGroupResult or None:
    if not group.cluster.inventory['services']['packages']['package_manager']['replace-repositories']:
        group.cluster.log.debug("Skipped - repos replacement disabled in configuration")
        return
    # all files in directory will be renamed: xxx.repo -> xxx.repo.bak
    # if there already any files with ".bak" extension, they should not be renamed to ".bak.bak"!
    return group.sudo("find %s -type f -name '%s.list' | "
                      "sudo xargs -t -iNAME mv -bf NAME NAME.bak" % ("/etc/apt/", repo_filename), **kwargs)


def add_repo(group, repo_data="", repo_filename="predefined", **kwargs) -> NodeGroupResult:
    # if repo_data is list, then convert it to string using join
    if isinstance(repo_data, list):
        repo_data_str = "\n".join(repo_data) + "\n"
    else:
        repo_data_str = str(repo_data)
    group.put(io.StringIO(repo_data_str), '%s/%s.list' % ("/etc/apt/sources.list.d/", repo_filename), sudo=True)
    return group.sudo(DEBIAN_HEADERS + 'apt clean && sudo apt update', **kwargs)


def clean(group, **kwargs) -> NodeGroupResult:
    return group.sudo(DEBIAN_HEADERS + "apt clean", **kwargs)


def install(group, include=None, exclude=None, **kwargs) -> NodeGroupResult:
    if include is None:
        raise Exception('You must specify included packages to install')

    if isinstance(include, list):
        include = ' '.join(include)
    command = DEBIAN_HEADERS + 'apt update && ' + \
              DEBIAN_HEADERS + 'sudo apt install -y %s' % include

    if exclude is not None:
        if isinstance(exclude, list):
            exclude = ','.join(exclude)
        command += ' --exclude=%s' % exclude

    return group.sudo(command, **kwargs)
    # apt fails to install (downgrade) package if it is already present and has higher version,
    # thus we do not need additional checks here (in contrast to yum)


def remove(group, include=None, exclude=None, **kwargs) -> NodeGroupResult:
    if include is None:
        raise Exception('You must specify included packages to remove')

    if isinstance(include, list):
        include = ' '.join(include)
    command = DEBIAN_HEADERS + 'apt purge -y %s' % include

    if exclude is not None:
        if isinstance(exclude, list):
            exclude = ','.join(exclude)
        command += ' --exclude=%s' % exclude

    return group.sudo(command, **kwargs)


def upgrade(group, include=None, exclude=None, **kwargs) -> NodeGroupResult:
    if include is None:
        raise Exception('You must specify included packages to upgrade')

    if isinstance(include, list):
        include = ' '.join(include)
    command = DEBIAN_HEADERS + 'apt update && ' + \
              DEBIAN_HEADERS + 'sudo apt upgrade -y %s' % include

    if exclude is not None:
        if isinstance(exclude, list):
            exclude = ','.join(exclude)
        command += ' --exclude=%s' % exclude

    return group.sudo(command, **kwargs)
