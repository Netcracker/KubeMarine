# Network Perfomance Benchmark

Source [https://github.com/Pharb/kubernetes-iperf3](https://github.com/Pharb/kubernetes-iperf3).

To check the cluster network performance, it is necessary to do the following:

1. Add the following configuration to the **plugins** section:
   ```yaml
   plugins:
     iperf3:
       install: true
       installation:
         procedures:
           - template: templates/plugins/iperf3.yaml.j2
             expect:
               pods:
                 - iperf3-server
                 - iperf3-clients
   ```

    For this plugin, it is possible to configure nodeSelector, so that all iperf3 pods will be ran only on particular nodes:
    ```yaml
    plugins:
      iperf3:
        nodeSelector:
          role: compute
    ```
    Also, it is possible to configure tolerations, so that iperf3 pods will be able to run on master, for example:
    ```yaml
    plugins:
      iperf3:
        tolerations:
          - key: node-role.kubernetes.io/control-plane
            effect: NoSchedule
    ```
   
2. Run the [installation](documentation/public/Installation.md) procedure and wait until it is completed.
3. Go to any control-plane node, and run the following script:
   ```bash
   #!/usr/bin/env bash
   set -eu
    
   CLIENTS=$(kubectl get pods -n iperf3 -l app=iperf3-client -o name | cut -d'/' -f2)
    
   for POD in ${CLIENTS}; do
     until $(kubectl get pod -n iperf3 ${POD} -o jsonpath='{.status.containerStatuses[0].ready}'); do
       echo "Waiting for ${POD} to start..."
       sleep 5
     done
     HOST=$(kubectl get pod -n iperf3 ${POD} -o jsonpath='{.status.hostIP}')
     kubectl exec  -n iperf3 -it ${POD} -- iperf3 -c iperf3-server -T "Client on ${HOST}" $@
     echo
   done
   ```
4. Once the benchmark is finished, remove the plugin using the following command:
   ```bash
   # kubectl delete --cascade -f /etc/kubernetes/iperf3.yaml
   ```
