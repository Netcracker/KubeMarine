from kubemarine.core import utils
from kubemarine.core.cluster import KubernetesCluster


def schedule_summary_report(cluster: KubernetesCluster):
    plugin_item = cluster.inventory['plugins']['kubernetes-dashboard']
    hostname = plugin_item['hostname']
    # Currently we declare that Dashboard UI is available only via HTTPS
    utils.schedule_summary_report(cluster.context, utils.SummaryItem.DASHBOARD_URL, f'https://{hostname}')
