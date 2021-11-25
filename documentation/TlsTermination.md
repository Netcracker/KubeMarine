## TLS termination on Nginx Ingress Controller

This is the default recommended approach to TLS termination on kubetool-installed environments. This approach is applicable when MTLS is not used in kubernetes and all the communications between pods are over plain HTTP.
High-level overview of this approach is shown on the following diagram.

![](/documentation/images/tls-termination-nginx.png)

Here, client creates HTTPS connection to TCP Load Balancer, which in turn proxies the traffic to Nginx Ingress Controller without TLS termination.
Nginx Ingress Controller uses default wildcard certificate to authenticate itself to a client and to terminate HTTPS connection.
To support multiple hostnames the certificate could use wildcard SANs.
Nginx Ingress Controller contacts applications using plain HTTP connection.
Thus, using this approach it is very easy to manage only one certificate in one place - TLS traffic will be terminated on nginx ingress controller using default certificate for all application ingresses.

To read more about nginx ingress controller default certificate visit [https://kubernetes.github.io/ingress-nginx/user-guide/tls/#default-ssl-certificate](https://kubernetes.github.io/ingress-nginx/user-guide/tls/#default-ssl-certificate).

**Limitations:**
- Adding new hostname might require to re-issue certificate, if new hostname do not match any previous wildcard SANs.
- Connections from nginx ingress controller to applications are HTTP, i.e. without encryption.
- L7 load balancing options could be customized through "ingress" resources only.

### How to install

To enable TLS termination on Nginx Ingress Controller using default certificate it is required to customize "nginx" plugin with a custom default certificate.
This could be done during:
- Installation, for details refer to [nginx plugin installation](/documentation/Installation.md#nginx-ingress-controller).
- On already installed Nginx Ingress Controller, using `certs_renew` maintenance procedure, for details refer to [certificate renew maintenance procedure](/documentation/Maintenance.md#configuring-certificate-renew-procedure-for-nginx-ingress-controller).

**Important:** the default certificate should be issued to wildcard hostnames, so that it could be used for all ingresses.

### Using Kubetool-provided TCP Load Balancer

Using kubetool you could install and configure HAProxy TCP Load Balancers in HA mode using VRRP.
For that you need to assign `balancer` role to some of your hosts, where HAProxy and Keepalived should be installed,
for more information see [`nodes` Installation Section](/documentation/Installation.md#nodes).
For instructions on how to configure vrrp IPs for balancer nodes see  [`vrrp_ips` Installation Section](/documentation/Installation.md#vrrp_ips).
For load balancer nodes hardware requirements see [Minimal Hardware Requirements](/documentation/Installation.md#minimal-hardware-requirements).

### Using Custom TCP Load Balancer

You could also use your own TCP Load balancer instead of kubetool-provided HAProxy.
In this case your custom TCP Load Balancer should meet following requirements:
1. Load Balancer should be fully configured and working before running cluster installation using kubetool.
2. Load Balancer internal and external vrrp IP addresses should be specified in `cluster.yaml`, see [`control_plain` Installation Section](/documentation/Installation.md#control_plain).
3. Load Balancer should be L4 pass-through TCP Load Balancer, without TLS termination.
4. Load Balancer should be Highly Available.
5. Load Balancer should have HTTPS (port 443) and Kubernetes API (port 6443) frontends.
6. HTTPS frontend should point to backend port 443 of worker nodes where Nginx Ingress Controller is installed.
7. Kubernetes API frontend should point to backend port 6443 of all master nodes.
8. Load Balancer backend configuration should be updated accordingly when new nodes are added or removed from cluster.
