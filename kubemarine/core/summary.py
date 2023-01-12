from tabulate import tabulate

from kubemarine.core.cluster import KubernetesCluster


def schedule_summary_report(cluster: KubernetesCluster, property: str, value: str):
    cluster.context.setdefault('summary_report', []).append([property, value])
    cluster.schedule_cumulative_point(print_summary)


def print_summary(cluster: KubernetesCluster):
    table = tabulate(cluster.context.get('summary_report'),
                     headers=["Property", "Value"],
                     tablefmt="pretty",
                     colalign=("left", "left"))
    cluster.log.info(table)
