from kubemarine.core import summary
from kubemarine.core.cluster import KubernetesCluster


def schedule_summary_report(cluster: KubernetesCluster):
    plugin_item = cluster.inventory['plugins']['kubernetes-dashboard']
    hostname = plugin_item['hostname']
    # Currently we declare that Dashboard UI is available only via HTTPS
    summary.schedule_summary_report(cluster, 'Dashboard UI', f'https://{hostname}')
