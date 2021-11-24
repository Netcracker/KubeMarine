import configparser
import io


def ls_repofiles(group, **kwargs):
    return group.sudo('ls -la /etc/yum.repos.d', **kwargs)


def backup_repo(group, repo_filename="*", **kwargs):
    if not group.cluster.inventory['services']['packages']['package_manager']['replace-repositories']:
        group.cluster.log.debug("Skipped - repos replacement disabled in configuration")
        return
    # all files in directory will be renamed: xxx.repo -> xxx.repo.bak
    # if there already any files with ".bak" extension, they should not be renamed to ".bak.bak"!
    return group.sudo("find /etc/yum.repos.d/ -type f -name '%s.repo' | "
                      "sudo xargs -t -iNAME mv -bf NAME NAME.bak" % repo_filename, **kwargs)


def add_repo(group, repo_data="", repo_filename="predefined", **kwargs):
    # if repo_data is dict, then convert it to string with config inside
    if isinstance(repo_data, dict):
        config = configparser.ConfigParser()
        for repo_id, data in repo_data.items():
            config[repo_id] = data
        repo_data = io.StringIO()
        config.write(repo_data)
    group.put(repo_data, '/etc/yum.repos.d/%s.repo' % repo_filename, sudo=True)
    return group.sudo('yum clean all && sudo yum updateinfo', **kwargs)


def clean(group, mode="all", **kwargs):
    return group.sudo("yum clean %s" % mode, **kwargs)


def install(group, include=None, exclude=None, **kwargs):
    if include is None:
        raise Exception('You must specify included packages to install')

    if isinstance(include, list):
        include = ' '.join(include)
    command = 'yum install -y %s' % include

    if exclude is not None:
        if isinstance(exclude, list):
            exclude = ','.join(exclude)
        command += ' --exclude=%s' % exclude
    command += f"; rpm -q {include}; if [ $? != 0 ]; then echo \"Failed to check version for some packages. " \
               f"Make sure packages are not already installed with higher versions. " \
               f"Also, make sure user-defined packages have rpm-compatible names. \"; exit 1; fi "
    install_result = group.sudo(command, **kwargs)

    return install_result


def remove(group, include=None, exclude=None, **kwargs):
    if include is None:
        raise Exception('You must specify included packages to remove')

    if isinstance(include, list):
        include = ' '.join(include)
    command = 'yum remove -y %s' % include

    if exclude is not None:
        if isinstance(exclude, list):
            exclude = ','.join(exclude)
        command += ' --exclude=%s' % exclude

    return group.sudo(command, **kwargs)


def upgrade(group, include=None, exclude=None, **kwargs):
    if include is None:
        raise Exception('You must specify included packages to upgrade')

    if isinstance(include, list):
        include = ' '.join(include)
    command = 'yum upgrade -y %s' % include

    if exclude is not None:
        if isinstance(exclude, list):
            exclude = ','.join(exclude)
        command += ' --exclude=%s' % exclude

    return group.sudo(command, **kwargs)
