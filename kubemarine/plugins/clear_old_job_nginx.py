# Checking jobs nginx for deletion

def check_job_for_nginx(cluster):
    first_control_plane = cluster.nodes['control-plane'].get_first_member(provide_node_configs=True)

    check_jobs = first_control_plane['connection'].sudo(f"kubectl get jobs -n ingress-nginx")
    if list(check_jobs.values())[0].stderr == "" and \
            cluster.inventory['plugins']['nginx-ingress-controller']['version'] >= "1.4.0":
        cluster.log.debug('Delete old jobs for nginx')
        first_control_plane['connection'].sudo(f"sudo kubectl delete job --all -n ingress-nginx", is_async=False)
    else:
        cluster.log.debug('There are no jobs to delete')
