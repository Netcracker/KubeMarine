# Copyright 2021-2023 NetCracker Technology Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

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
