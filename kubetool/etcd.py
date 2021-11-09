import io
import json
import time
from kubetool.core.group import NodeGroup


# the methods requires etcdctl.sh to be installed on all active master nodes during thirdparties task.

def remove_members(group: NodeGroup):
    log = group.cluster.log

    masters = group.cluster.nodes["master"]
    managing_master = masters.get_unchanged_nodes().get_any_member()

    log.verbose(f"etcd will be managed using {managing_master.get_nodes_names()[0]}.")
    output = managing_master.sudo("etcdctl member list").get_simple_out().splitlines()

    etcd_members = {}
    for line in output:
        params = [p.strip() for p in line.split(sep=',')]
        # 6 is expected number of comma-separated parameters of an etcd member
        if len(params) == 6:
            etcd_members[params[2]] = params[0]
        else:
            log.warning("Unexpected line in 'etcdctl member list' output: " + line)

    log.verbose(f"Found etcd members {list(etcd_members.keys())}")
    unexpected_members = etcd_members.keys() - set(masters.get_nodes_names())
    if unexpected_members:
        log.warning(f"Found unexpected etcd members {list(unexpected_members)}")

    for node_name in group.get_nodes_names():
        if node_name in etcd_members:
            command = "etcdctl member remove " + etcd_members[node_name]
            log.verbose(f"Removing found etcd member {node_name}...")
            managing_master.sudo(command)
        else:
            log.verbose(f"Skipping {node_name} as it is not among etcd members.")

# the method check etcd endpoints health until all endpoints are healthy or retries are exhausted
def wait_for_health(cluster, connection):

    log = cluster.log
    timeout = cluster.globals['etcd']['health']['timeout']
    retries = cluster.globals['etcd']['health']['retries']

    while retries > 0:
        etcd_health_raw = connection.sudo('etcdctl endpoint health --cluster -w json'
                                           , is_async=False, hide=True).get_simple_out()
        log.verbose(etcd_health_raw)
        etcd_health_list = json.load(io.StringIO(etcd_health_raw.strip()))

        health = 0
        for etcd_health in etcd_health_list:
            if etcd_health.get('health'):
                health += 1

        if health == len(etcd_health_list):
            log.debug('All ETCD members are healthy!')
            return
        else:
            log.debug('Wait for ETCD cluster is not healthy!')
            time.sleep(timeout)
            retries -= 1

    raise Exception('ETCD cluster is still not healthy!')

