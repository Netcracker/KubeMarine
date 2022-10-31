1. Install latest [Docker CE](https://docs.docker.com/engine/install/)
2. Ensure Docker Engine is running
3. Clone this repository: `git clone https://github.com/Netcracker/KubeMarine.git`
4. Navigate inside project directory: `cd kubemarine`
5. Run building: `docker build . -t kubemarine --no-cache --progress=plain`
 Now you can proceed to run Kubemarine from container, for example:
   ```
   docker run -it --mount type=bind,source=/root/cluster.yaml,target=/opt/kubemarine/cluster.yaml --mount type=bind,source=/root/rsa_key,target=/opt/kubemarine/rsa_key kubemarine install -c /opt/kubemarine/cluster.yaml
   ```
   *Note:*: do not forget to pass inventory file and connection key inside container.
   For more execution details refer to ["Installation of Kubernetes using CLI" guide on Github](https://github.com/Netcracker/kubemarine/blob/main/documentation/Installation.md#installation-of-kubernetes-using-cli).

*Hint:* it is possible to pass building arguments (use `--build-arg`) to build using binary (argument `BUILD_TYPE=binary`) or build image with testing tools included (argument `BUILD_TYPE=test`).
