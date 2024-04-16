The following functions are installed in this section.  

**Table of Content**

- [TLS Termination on Nginx Ingress Controller](#tls-termination-on-nginx-ingress-controller)
  - [How to Install](#how-to-install)
  - [Using Kubemarine-provided TCP Load Balancer](#using-kubemarine-provided-tcp-load-balancer)
  - [Using Custom TCP Load Balancer](#using-custom-tcp-load-balancer)
- [Advanced Load Balancing Techniques](#advanced-load-balancing-techniques)
  - [Allow and Deny Lists](#allow-and-deny-lists)
  - [Preserving Original HTTP Headers](#preserving-original-http-headers)
- [Maintenance Mode](#maintenance-mode)

## TLS Termination on Nginx Ingress Controller

This is the default recommended approach to the TLS termination on kubemarine-installed environments. This approach is applicable when MTLS is not used in kubernetes and all communications between the pods are over plain HTTP.
A high-level overview of this approach is shown in the following image.

![](/documentation/images/tls-termination-nginx.png)

Here, the client creates a HTTPS connection to the TCP load balancer, which in turn proxies the traffic to the Nginx Ingress Controller without a TLS termination.
Nginx Ingress Controller uses a default wildcard certificate to authenticate itself to a client and to terminate the HTTPS connection.
To support multiple hostnames, the certificate can use wildcard SANs.
Nginx Ingress Controller contacts applications using plain HTTP connection.
Thus using this approach, it is very easy to manage only one certificate in one place - TLS traffic is terminated on the Nginx Ingress Controller using the default certificate for all application ingresses.

For more information about Nginx Ingress Controller default certificate, visit [https://kubernetes.github.io/ingress-nginx/user-guide/tls/#default-ssl-certificate](https://kubernetes.github.io/ingress-nginx/user-guide/tls/#default-ssl-certificate).

**Limitations**

This approach has the following limitations:

* Adding a new hostname might require to re-issue the certificate, if the new hostname does not match any previous wildcard SANs.
* Connections from the Nginx Ingress Controller to applications are through HTTP; thus, without an encryption.
* L7 load balancing options can be customized through "ingress" resources only.

### How to Install

To enable TLS termination on Nginx Ingress Controller using the default certificate, it is required to customize the "nginx" plugin with a custom default certificate.
This can be done during:

* Installation; for details, refer to [nginx plugin installation](/documentation/Installation.md#nginx-ingress-controller).
* On an already installed Nginx Ingress Controller, using the `certs_renew` maintenance procedure. For details, refer to [certificate renew maintenance procedure](/documentation/Maintenance.md#configuring-certificate-renew-procedure-for-nginx-ingress-controller).

**Important**: The default certificate should be issued to wildcard hostnames, so that it can be used for all ingresses.

### Using Kubemarine-provided TCP Load Balancer

Using kubemarine you can install and configure HAProxy TCP load balancers in the HA mode using VRRP.
To do so, assign a `balancer` role to the hosts where HAProxy and Keepalived should be installed.
For more information, refer to the [`nodes` Installation Section](/documentation/Installation.md#nodes).
For instructions on how to configure VRRP IPs for balancer nodes, refer to the [`vrrp_ips` Installation Section](/documentation/Installation.md#vrrp_ips).
For load balancer nodes' hardware requirements, refer to [Minimal Hardware Requirements](/documentation/Installation.md#minimal-hardware-requirements).

### Using Custom TCP Load Balancer

You can also use your own TCP load balancer instead of kubemarine-provided HAProxy.
In this case, your custom TCP load balancer should meet the following requirements:

* The load balancer should be fully configured and working before running the cluster installation using kubemarine.
* The load balancer's internal and external VRRP IP addresses should be specified in `cluster.yaml`. For more information, refer to the [`control_plain` Installation Section](/documentation/Installation.md#control_plain).
* The load balancer should be an L4 pass-through TCP load balancer, without TLS termination.
* The load balancer should be Highly Available.
* The load balancer should have HTTPS (port 443) and Kubernetes API (port 6443) frontends.
* The HTTPS frontend should point to backend port 443 of worker nodes where Nginx Ingress Controller is installed.
* The Kubernetes API frontend should point to backend port 6443 of all control-plane nodes.
* The load balancer backend configuration should be updated accordingly when new nodes are added or removed from a cluster.

## Advanced Load Balancing techniques

### Allow and Deny Lists

Sometimes, it may be required to allow or deny only specific requests based on some criteria. 
The possible criteria depends on the type of the load balancer (TCP or HTTP).

#### Allow and Deny Lists on TCP Load Balancer

For a TCP Load Balancer, it is possible to introduce both allow and deny lists based on the source IP address.
For example, see the HAProxy ACL basics on [http://cbonte.github.io/haproxy-dconv/configuration-1.5.html#7.1](http://cbonte.github.io/haproxy-dconv/configuration-1.5.html#7.1).
An example of a HAProxy configuration to create an allow list based on source IP addresses is as follows:

```
frontend www
  bind *:80
  mode tcp
  acl network_allowed src 1.1.1.1 2.2.2.2
  tcp-request connection reject if !network_allowed
  use_backend my_backend_server
```

The drawback of this method is that the TCP load balancer uses these criteria for all the requests.
Sometimes it is required that the filtering happens only for some specific hostnames.
To match against hostnames, it is required to configure the allow list on a HTTP load balancer (Nginx Ingress Controller).

#### Allow List on Nginx Ingress Controller

For the Nginx Ingress Controller, it is possible to configure allow lists based on both the hostname and source IP addresses.
For more information about the Nginx Ingress Controller `whitelist-source-range` annotation, refer to [https://kubernetes.github.io/ingress-nginx/user-guide/nginx-configuration/annotations/#whitelist-source-range](https://kubernetes.github.io/ingress-nginx/user-guide/nginx-configuration/annotations/#whitelist-source-range).
An example of an ingress configuration to create an allow list based on source IP addresses for a particular hostname is as follows:

```
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: ingress-myservice-whitelist
  annotations:
    nginx.ingress.kubernetes.io/whitelist-source-range: "10.0.0.0/24,172.10.0.1"
spec:
  ingressClassName: nginx
  rules:
  - host: whitelist.myservicea.foo.org
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: myservice
            port:
              number: 80
```

In this example, the `whitelist.myservicea.foo.org` hostname is available only from IP address `172.10.0.1` and subnet `10.0.0.0/24`.

### Preserving Original HTTP Headers

The TCP load balancer does not modify the HTTP response/request headers. 
The Nginx Ingress Controller also does not modify **custom** HTTP headers. 
However, the Nginx Ingress Controller may modify some well-known headers as described below:
1. Nginx Ingress Controller always drops some response headers, 
particularly, `Date`, `Server`, `X-Pad`, and `X-Accel-...`. For more information, see [http://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_hide_header](http://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_hide_header).
2. Nginx Ingress Controller by default sets its own values for `X-Forwarded-*` headers.
If you have to preserve original values for these headers, refer to the `use-forwarded-header` config map option at [https://kubernetes.github.io/ingress-nginx/user-guide/nginx-configuration/configmap/#use-forwarded-headers](https://kubernetes.github.io/ingress-nginx/user-guide/nginx-configuration/configmap/#use-forwarded-headers).
This is only required if you have another HTTP LB in front of the Nginx Ingress Controller, which sets these headers.
3. Nginx Ingress Controller does not forward the `Expect` header. 
This issue can be solved by adding the "proxy_set_header" field in the NGINX configuration with value, "Expect $http_expect". An example of `cluster.yaml` configuration is as follows:

```
plugins:
  nginx-ingress-controller:
    custom_headers:
      Expect: $http_expect
```

## Maintenance Mode

Sometimes, it may be required to perform some maintenance operations on the cluster
during which external "business" traffic should be temporarily stopped,
while at the same time the cluster API/UI should still be available for technical traffic (administrative tasks).
For example, such maintenance operations may be software updates or DR scenarios.

There are multiple ways to support such "maintenance mode".
Kubemarine supports maintenance mode on the level of HAProxy Load Balancer using two different endpoints:

- "Business" endpoint, which is served on particular vIP (e.g. `1.1.1.1`)
- Additional "technical" endpoint, which is served on separate vIP (e.g. `2.2.2.2`)

Both endpoints are served by the same HAProxy instances and route to the same backends (k8s API / ingress controller).
The business endpoint is used for business traffic, and the technical endpoint is used for technical traffic.
Normally, both these endpoints work, so any traffic is served.
However, if maintenance mode should be enabled, HAProxy configuration could be changed,
so that the business endpoint no longer forwards traffic to backends, instead returning an HTTP error.
In this mode, only the technical traffic is served normally.

### How to Use Maintenance Mode

To start using Maintenance Mode on the Kubemarine cluster, it is required to do two things during the cluster installation:

1. Configure at least two vIP - one for business traffic and one for technical traffic.
   Business vIP should be marked with [`params.maintenance-type: "not bind"`](/documentation/Installation.md#maintenance-type) to be "dropped" during the maintenance mode.

1. Maintenance Mode support should be enabled using [`haproxy.maintenance_mode: True`](/documentation/Installation.md#maintenance-mode).
   This does not enable the maintenance mode on HAProxy immediately, instead it uploads **additional** maintenance configuration on HAProxy nodes, which could be then used to enable the maintenance mode.

After these steps, HAProxy nodes support enabling the maintenance mode.
To actually move HAProxy to maintenance mode, it is required to change HAProxy configuration from `haproxy.cfg` to `haproxy-mntc.cfg`.
To do this without conflicting with Kubemarine, use the following steps:

1. Create HAProxy systemd drop-in directory, if not created already. For example, if the HAProxy service is named `haproxy.service`,
you need to create the `/etc/systemd/system/haproxy.service.d` directory.
1. In this directory, create a file named `EnvFile` with the following content:

      ```csv
      CONFIG=/etc/haproxy/haproxy-mntc.cfg
      ```

1. In the same directory, create a file named `select.conf` with the path to `EnvFile` created above:

      ```csv
      [Service]
      EnvironmentFile=/etc/systemd/system/haproxy.service.d/EnvFile
      ```

1. Restart the HAProxy service using the command `sudo systemctl daemon-reload; sudo systemctl restart haproxy`
1. To disable maintenance mode, change `EnvFile` content to use the default configuration and restart HAProxy again:

      ```csv
      CONFIG=/etc/haproxy/haproxy.cfg
      ```
