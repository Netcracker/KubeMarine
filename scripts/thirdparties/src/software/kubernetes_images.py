from collections import OrderedDict
from typing import List, Dict

from . import CompatibilityMap, thirdparties
from ..shell import run
from ..tracker import ChangesTracker


def get_k8s_images_mapping(k8s_versions: List[str]) -> Dict[str, Dict[str, str]]:
    k8s_images_mapping = OrderedDict()
    for k8s_version in k8s_versions:
        kubeadm_path = thirdparties.resolve_local_path('/usr/bin/kubeadm', k8s_version)
        run(['chmod', '+x', kubeadm_path])
        images_list = run([kubeadm_path, 'config', 'images', 'list', '--kubernetes-version', k8s_version])\
            .strip().split('\n')
        for item in images_list:
            image_path, version = item.split(':')
            image_name = '/'.join(image_path.split('/')[1:])
            k8s_images_mapping.setdefault(image_name, OrderedDict()).setdefault(k8s_version, version)

    return k8s_images_mapping


def sync(tracker: ChangesTracker, kubernetes_versions: dict):
    """
    Fetch all kubernetes images from 'kubeadm' executable and actualize the compatibility_map.
    # TODO if pause version is changed, it is necessary to write patch that will reconfigure containerd.
    """
    k8s_versions = list(kubernetes_versions)
    k8s_images_mapping = get_k8s_images_mapping(k8s_versions)
    image_names = list(k8s_images_mapping)

    compatibility_map = CompatibilityMap(tracker, "kubernetes_images.yaml", image_names)
    for image_name in image_names:
        k8s_image_versions = k8s_images_mapping[image_name]
        compatibility_map.prepare_software_mapping(image_name, list(k8s_image_versions))

        for k8s_version, image_version in k8s_image_versions.items():
            if image_name in kubernetes_versions[k8s_version]:
                image_version = kubernetes_versions[k8s_version][image_name]
            new_settings = {
                'version': image_version
            }
            compatibility_map.reset_software_settings(image_name, k8s_version, new_settings)

    compatibility_map.flush()
