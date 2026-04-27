
import os
import yaml
from kubemarine import plugins
from kubemarine.core import utils
from kubemarine.core.cluster import KubernetesCluster
from kubemarine.core.yaml_merger import default_merger


def get_images_versions(chart_version: str) -> dict[str, str]:
    values = utils.load_yaml(utils.get_internal_resource_path(
        f"plugins/charts/openstack-cinder-csi-{chart_version}/values.yaml"
    ))
    chartManifest = utils.load_yaml(utils.get_internal_resource_path(
        f"plugins/charts/openstack-cinder-csi-{chart_version}/Chart.yaml"
    ))
    return {
        "attacher": values["csi"]["attacher"]["image"]["tag"],
        "provisioner": values["csi"]["provisioner"]["image"]["tag"],
        "snapshotter": values["csi"]["snapshotter"]["image"]["tag"],
        "resizer": values["csi"]["resizer"]["image"]["tag"],
        "livenessprobe": values["csi"]["livenessprobe"]["image"]["tag"],
        "nodeDriverRegistrar": values["csi"]["nodeDriverRegistrar"]["image"]["tag"],
        "plugin": chartManifest["appVersion"],
    }

def apply_cinder_chart(cluster: KubernetesCluster) -> None:
    cinder_plugin = cluster.inventory["plugins"]["openstack-cinder-csi"]
    chart_version = cinder_plugin["version"]

    helm_plugin_config = {
        "chart_path": utils.get_internal_resource_path(f"plugins/charts/openstack-cinder-csi-{chart_version}"),
        "namespace": cinder_plugin["namespace"],
        "release": cinder_plugin["releaseName"],
        "take_ownership": True,
    }

    cinder_image = "provider-os/cinder-csi-plugin"
    if cinder_plugin["version"] == "2.2.0":
        cinder_image = "k8scloudprovider/cinder-csi-plugin"
    if "registry" in cinder_plugin["installation"]:
        registry = cinder_plugin["installation"]["registry"]
        helm_plugin_config["values"] = {
            "csi": {
                "attacher": {
                    "image":{
                        "repository": f"{registry}/sig-storage/csi-attacher"
                    }
                },
                "provisioner": {
                    "image":{
                        "repository": f"{registry}/sig-storage/csi-provisioner"
                    }
                },
                "snapshotter": {
                    "image":{
                        "repository": f"{registry}/sig-storage/csi-snapshotter"
                    }
                },
                "resizer": {
                    "image":{
                        "repository": f"{registry}/sig-storage/csi-resizer"
                    }
                },
                "livenessprobe": {
                    "image":{
                        "repository": f"{registry}/sig-storage/livenessprobe"
                    }
                },
                "nodeDriverRegistrar": {
                    "image":{
                        "repository": f"{registry}/sig-storage/csi-node-driver-registrar"
                    }
                },
                "plugin": {
                    "image":{
                        "repository": f"{registry}/{cinder_image}"
                    }
                },
            }
        }

    helm_plugin_config["values"] = default_merger.merge(helm_plugin_config["values"], cinder_plugin["values"])
    utils.dump_file(
        cluster.context, 
        yaml.dump(helm_plugin_config["values"]), "openstack-cinder-csi-values.yaml", 
        dump_location=True
    )
    plugins.apply_helm(cluster=cluster, config=helm_plugin_config)