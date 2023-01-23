import enum
from functools import total_ordering
from typing import Dict, Callable

from kubemarine.core import log
from kubemarine.core.cluster import KubernetesCluster


@total_ordering
class SummaryItem(enum.Enum):
    DASHBOARD_URL = (1, "Dashboard URL")
    CONTROL_PLANES = (2, "Running Control Planes")
    WORKERS = (3, "Running Workers")
    ACCOUNT_TOKENS = (4, "Account Tokens File")
    EXECUTION_TIME = (5, "Elapsed")

    def __init__(self, order, text):
        self.order = order
        self.text = text

    def __lt__(self, other):
        return self.order < other.order


def schedule_report(context: dict, property: SummaryItem, value: str):
    context.setdefault('summary_report', {})[property] = value


def schedule_delayed_report(cluster: KubernetesCluster, call: Callable[[KubernetesCluster], None]):
    cluster.context.setdefault('delayed_summary_report', []).append(call)
    cluster.schedule_cumulative_point(exec_delayed)


def print_summary(context: dict, logger: log.EnhancedLogger):
    summary_items: Dict[SummaryItem, str] = context.get('summary_report', {})
    max_length = max(len(si.text) for si in summary_items.keys())
    logger.info('')
    for si, value in sorted(summary_items.items()):
        key = si.text + ': ' + (' ' * (max_length - len(si.text)))
        logger.info(key + value)


def exec_delayed(cluster: KubernetesCluster):
    for call in cluster.context.get('delayed_summary_report', []):
        call(cluster)
