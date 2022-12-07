# Copyright 2021-2022 NetCracker Technology Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


import io
import ruamel.yaml
import sys
import os
import importlib
import logging

from jinja2 import Template
from urllib import request
from copy import deepcopy


# config path
CONFIG = "./thirdpaties_update.yaml"

FORMAT = '%(asctime)s %(name)s %(levelname)s %(message)s'
logging.basicConfig(format=FORMAT)
logger = logging.getLogger('thirdparties_update')


def main():


    # read config
    if len(sys.argv) < 2:
        config_path = CONFIG
    else:
        config_path = sys.argv[1]

    config = load_yaml(config_path)

    # backup globals.yaml
    globals_file = f"{config['kubemarine']['dir']}/{config['kubemarine']['globals']}"
    os.system(f"cp --backup=numbered {globals_file} {globals_file}.old")
    # load globals.yaml
    globals_yaml = load_yaml(f"{globals_file}.old")

    # check current latest version
    last = len(globals_yaml['compatibility_map']['software']['kubeadm']) - 1
    versions_list = []
    for version in globals_yaml['compatibility_map']['software']['kubeadm']:
        versions_list.append(version)
    versions_list.sort()
    latest_version = versions_list[last]


    logger.debug(f"Current latest supported version: {latest_version}")
    new_version = config['kubernetesVersion']
    logger.debug(f"New version: {new_version}")
    new_version_minor = '.'.join(new_version.split('.')[:-1])

    # check if globals.yaml needs to be updated
    is_update = False
    is_update_minor = False
    if latest_version != new_version:
        # check if new version is higher or equal
        # should the major version be checked?
        if latest_version.split('.')[1] == new_version.split('.')[1]:
            if int(latest_version.split('.')[2]) < int(new_version.split('.')[2]):
                # patch version is higher
                is_update = True
        elif int(latest_version.split('.')[1]) < int(new_version.split('.')[1]):
            # minor version is higher
            is_update = True
            is_update_minor = True
        else:
            raise Exception("Kubernetes version in config must be equal or higher than version in 'defaults.yaml'")

    soft_minor_version = ['calico', 'nginx-ingress-controller', 'kubernetes-dashboard', 'local-path-provisioner', 'pause']

    # add to globals new maps for new Kubernetes version
    for item in globals_yaml['compatibility_map']['software'].keys():
        if is_update:
            if item not in soft_minor_version:
                globals_yaml['compatibility_map']['software'][item][new_version] = \
                        deepcopy(globals_yaml['compatibility_map']['software'][item][latest_version])
        if is_update_minor:
            if item in soft_minor_version:
                globals_yaml['compatibility_map']['software'][item][new_version_minor] = \
                        deepcopy(globals_yaml['compatibility_map']['software'][item][latest_version])
    # swap new version with the previous in maps
    for plugin in config['plugins'].keys():
        if item in soft_minor_version:
            for ver in config['plugins'][plugin]['compatible_versions']:
                globals_yaml['compatibility_map']['software'][plugin][ver]['version'] = config['plugins'][plugin]['version']
        else:
            for ver in config['plugins'][plugin]['compatible_versions']:
                for patch_ver in globals_yaml['compatibility_map']['software'][plugin].keys():
                    if '.'.join(patch_ver.split('.')[:-1]) == ver:
                        globals_yaml['compatibility_map']['software'][plugin][patch_ver]['version'] = \
                                config['plugins'][plugin]['version']
            

    # save changes in globals.yaml
    save_yaml(globals_file, globals_yaml)
    if 'demo' in sys.modules:
        del sys.modules["demo"]
    from kubemarine import demo

    # generate fake cluster
    inventory = demo.generate_inventory(**demo.MINIHA)

    # set Kubernetes version
    inventory['services']['kubeadm'] = {}
    inventory['services']['kubeadm']['kubernetesVersion'] = config['kubernetesVersion']
    # set PSS as default for Kubernetes v1.25 and higher
    if new_version.split('.')[1] >= "25":
        inventory['rbac'] = {}
        inventory['rbac']['admission'] = "pss"

    cluster = demo.new_cluster(inventory)

    images = {}
    # preserve images for system services, it's necessary for 'description.yaml'
    if latest_version == new_version:
        download(cluster.inventory['services']['thirdparties']['/usr/bin/kubeadm']['source'],
                 f"{config['default']['dest']}/kubeadm_init", cluster)
        images.update(get_k8s_images(f"{config['default']['dest']}/kubeadm_init"))

    # download original plugins YAMLs and change images
    for plugin in config['plugins'].keys():
        for plugin_inv in cluster.inventory['plugins'].keys():
            if plugin == plugin_inv:
                for item in cluster.inventory['plugins'][plugin_inv]['installation']['procedures']:
                    if item.get('python', ''):
                        destination = item['python']['arguments'][f'{plugin}_original_yaml']
                        source = cluster.inventory['plugins'][plugin_inv]['source']
                        cluster.log.debug(f"The {plugin} plugin YAML manifest source: {source}")
                        yaml_file = f"{config['kubemarine']['dir']}/{destination}"
                        cluster.log.debug(f"The {plugin} plugin YAML manifest destination: {yaml_file}")
                        download(f"{source}", yaml_file, cluster)
                        images.update(get_manifest_images(yaml_file))

    # download binaries, calculate SHA1, and change 'globals.yaml'
    kube_list = ['/usr/bin/kubeadm', '/usr/bin/kubelet', '/usr/bin/kubectl'] 
    os.system(f"mkdir -p {config['default']['dest']}")
    for item, param in cluster.inventory['services']['thirdparties'].items():
        thirdparty = item.split('/')[-1]
        cluster.log.debug(f"The {thirdparty} thirdpraty source {param['source']}")
        cluster.log.debug(f"The {thirdparty} thirdpraty destination: {config['default']['dest']}/{thirdparty}")
        if item in kube_list:
            download(param['source'], f"{config['default']['dest']}/{thirdparty}", cluster)
            sha1 = digest_sha1(f"{config['default']['dest']}/{thirdparty}")
            cluster.log.debug(f"The {thirdparty} thirdparty has SHA1: {sha1}")
            globals_yaml['compatibility_map']['software'][thirdparty][new_version]['sha1'] = sha1
            if item == '/usr/bin/kubeadm':
                images.update(get_k8s_images(f"{config['default']['dest']}/{thirdparty}"))
        # '/usr/bin/calicoctl' has dedicated procedure
        elif item == '/usr/bin/calicoctl':
            download(param['source'], f"{config['default']['dest']}/{thirdparty}", cluster)
            sha1 = digest_sha1(f"{config['default']['dest']}/{thirdparty}")
            cluster.log.debug(f"The {thirdparty} thirdparty has SHA1: {sha1}")
            for ver in config['plugins']['calico']['compatible_versions']:
                globals_yaml['compatibility_map']['software']['calico'][ver]['sha1'] = sha1
        # '/usr/bin/crictl.tar.gz' has dedicated procedure
        elif item == '/usr/bin/crictl.tar.gz':
            download(param['source'], f"{config['default']['dest']}/{thirdparty}", cluster)
            sha1 = digest_sha1(f"{config['default']['dest']}/{thirdparty}")
            cluster.log.debug(f"The {thirdparty} thirdparty has SHA1: {sha1}")
            globals_yaml['compatibility_map']['software']['crictl'][new_version]['sha1'] = sha1

    raw = {}
    raw['calicoctl'] = config['plugins']['calico']['version']
    raw['crictl'] = globals_yaml['compatibility_map']['software']['crictl'][new_version]['version']
    for item in ['kubeadm', 'kubelet', 'kubectl']:
        raw[item] = new_version
    
    # save result 'global.yaml'
    save_yaml(globals_file, globals_yaml)
    if 'demo' in sys.modules:
        del sys.modules["demo"]
    from kubemarine import demo

    # perform acceptance tests for plugins
    #test_plugins()

    # create new version of 'description.yaml'
    description_k8s_path = "./description.yaml.j2"
    # render k8s-sources Jinja2 template
    description_yaml_j2 = Template(open(description_k8s_path).read()).render(images=images, inventory=cluster.inventory, raw=raw)
    yaml = ruamel.yaml.YAML(typ='safe')
    description_yaml = yaml.load(description_yaml_j2)
    description_path = f"{config['default']['dest']}/description.yaml"
    # save new version of 'description.yaml'
    save_yaml(description_path, description_yaml)

    # TODO: add new images if the new images are detected

    # TODO: create RETPSM ticket text

    return True


def download(source_url, filepath, cluster, backup=True):
    """
    The method download the binary or YAML file from URL
    :param source_url: URL where the file stored
    :param filepath: destination file
    :param backup: save the copy of destination file if the destination file alredy exists
    """
    try:
        if backup:
            if os.path.isfile(filepath):
                os.system(f"cp --backup=numbered {filepath} {filepath}.bak")
        request.urlretrieve(source_url, filepath)
    except Exception as exc:
        cluster.log.error(f"The error is occurred during the download {source_url} to {filepath}:", exc)


def digest_sha1(filepath):
    """
    The method calculate SHA1 for binary file
    :param filepath: for that file the hash should be calculated
    """
    result = os.popen(f"openssl dgst -sha1 -c {filepath}")
    sha1 = result.read().replace(':', '').split('=')[1][1:-1]
    return sha1


def get_k8s_images(filepath):
    """
    The method gets images from kubeadm
    :param filepath: the path where the 'kubeadm' is stored
    """
    images = {}
    os.system(f"chmod +x {filepath}")
    result = os.popen(f"{filepath} config images list")
    images_list = result.read().split('\n')
    for item in images_list:
        if item:
            key = item.split('/')[1].split(':')[0]
            images[key] = '/'.join(item.split('/')[1:])
    return images


def get_manifest_images(filepath):
    """
    The method gets images from yaml file
    :param filepath: the path where the YAML manifest file is stored
    """
    images = {}
    result = os.popen(f"grep 'image:' {filepath}")
    images_list = result.read().split('\n')
    for item in images_list:
        if item:
            pref = item.split('/')[1]
            suff = item.split('/')[2].split(':')[0]
            image = '/'.join(item.split('/')[1:])
            images[f"{pref}-{suff}"] = image
    return images


def test_plugins(plugins):
    """
    The method tests list of YAML files on fake cluster
    :param plugind: the plugins list that should be processed
    """
    for plugin, options in plugins.items():
        if len(options):
            result = test_fns[plugin](options)
        else:
            result = test_fns[plugin]()


def test_calico():
    """
    The method tests calico enrichment methods on fake cluster
    """
    from kubemarine import demo
    from kubemarine.plugins import calico
    inventory = demo.generate_inventory(**demo.FULLHA_KEEPALIVED)
    cluster = demo.new_cluster(inventory)
    for item in inventory['plugins']['calico']['installation']['procedures']:
        if item.get('python', ''):
            calico_original_yaml = f"{config['kubmarine']['dir']}/{item['python']['arguments']['calico_original_yaml']}"
            calico_yaml = f"{config['kubemarine']['dir']}/{item['python']['arguments']['calico_yaml']}"
    calico.apply_calico_yaml(cluster, calico_original_yaml, calico_yaml, is_test=True)
    return True


#def load_yaml(filepath, cluster):
def load_yaml(filepath):
    """
    The method implements the parse YAML file
    :param filepath: Path to file that should be parsed
    """
    yaml = ruamel.yaml.YAML(typ='safe')
    yaml_dict = {}
    try:
        with open(filepath, 'r') as stream:
            yaml_dict = yaml.load(stream)
        return yaml_dict
    except Exception as exc:
        logger.error(f"Failed to load {filepath}", exc)


#def save_yaml(filepath, yaml_dict, cluster):
def save_yaml(filepath, yaml_dict):
    """
    The method implements the dumping some dictionary as the YAML file
    :param filepath: Path to file that should be created as the result
    """
    yaml = ruamel.yaml.YAML()
    try:
        with open(filepath, 'w') as stream:
            yaml.dump(yaml_dict, stream)
            logger.debug(f"The {filepath} file has been saved successfully")
    except Exception as exc:
        logger.error(f"Failed to save {filepath}", exc)

# test functions for plugins
test_fns = {
    "calico": test_calico
}


if __name__ == '__main__':
    main()
