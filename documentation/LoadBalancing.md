The following functions are installed in this section.  

**Table of Content**

- [TLS Termination on Nginx Ingress Controller](#tls-termination-on-nginx-ingress-controller)
  - [How to Install](#how-to-install)
  - [Using Kubetool-provided TCP Load Balancer](#using-kubetool-provided-tcp-load-balancer)
  - [Using Custom TCP Load Balancer](#using-custom-tcp-load-balancer)
- [Advanced Load Balancing Techniques](#advanced-load-balancing-techniques)
  - [Allow and Deny Lists](#allow-and-deny-lists)
  - [Preserving Original HTTP Headers](#preserving-original-http-headers)

## TLS Termination on Nginx Ingress Controller

This is the default recommended approach to the TLS termination on kubetool-installed environments. This approach is applicable when MTLS is not used in kubernetes and all communications between the pods are over plain HTTP.
A high-level overview of this approach is shown in the following image.

![](/documentation/images/tls-termination-nginx.png)

Here, the client creates a HTTPS connection to the TCP Load Balancer, which in turn proxies the traffic to the Nginx Ingress Controller without a TLS termination.
Nginx Ingress Controller uses a default wildcard certificate to authenticate itself to a client and to terminate the HTTPS connection.
To support multiple hostnames, the certificate can use wildcard SANs.
Nginx Ingress Controller contacts applications using plain HTTP connection.
Thus using this approach, it is very easy to manage only one certificate in one place - TLS traffic is terminated on the Nginx Ingress Controller using the default certificate for all application ingresses.

For more information about Nginx Ingress Controller default certificate, visit [https://kubernetes.github.io/ingress-nginx/user-guide/tls/#default-ssl-certificate](https://kubernetes.github.io/ingress-nginx/user-guide/tls/#default-ssl-certificate).

**Limitations**

This approach has the following limitations:

- Adding a new hostname might require to re-issue the certificate, if the new hostname does not match any previous wildcard SANs.
- Connections from the Nginx Ingress Controller to applications are through HTTP; thus, without an encryption.
- L7 load balancing options can be customized through "ingress" resources only.

### How to Install

To enable TLS termination on Nginx Ingress Controller using the default certificate, it is required to customize the "nginx" plugin with a custom default certificate.
This can be done during:

- Installation; for details, refer to [nginx plugin installation](/documentation/Installation.md#nginx-ingress-controller).
- On an already installed Nginx Ingress Controller, using the `certs_renew` maintenance procedure. For details, refer to [certificate renew maintenance procedure](/documentation/Maintenance.md#configuring-certificate-renew-procedure-for-nginx-ingress-controller).

**Important**: The default certificate should be issued to wildcard hostnames, so that it can be used for all ingresses.

### Using Kubetool-provided TCP Load Balancer

Using kubetool you can install and configure HAProxy TCP Load Balancers in the HA mode using VRRP.
To do so, assign a `balancer` role to the hosts where HAProxy and Keepalived should be installed.
For more information, see [`nodes` Installation Section](/documentation/Installation.md#nodes).
For instructions on how to configure VRRP IPs for balancer nodes, see  [`vrrp_ips` Installation Section](/documentation/Installation.md#vrrp_ips).
For load balancer nodes hardware requirements, see [Minimal Hardware Requirements](/documentation/Installation.md#minimal-hardware-requirements).

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


## Advanced Load Balancing techniques

### Allow and deny lists
Sometimes it is required to allow or deny only specific requests, based on some criteria. 
Possible criteria depend on the type of the load balancer (TCP or HTTP).

#### Allow and deny lists on TCP load balancer
For TCP Load Balancer it is possible to introduce both allow and deny lists based on source IP address.
For example, see HAProxy ACL basics: [http://cbonte.github.io/haproxy-dconv/configuration-1.5.html#7.1](http://cbonte.github.io/haproxy-dconv/configuration-1.5.html#7.1).
An example HAProxy configuration to create allow list based on source IP addresses:
```
frontend www
  bind *:80
  mode tcp
  acl network_allowed src 1.1.1.1 2.2.2.2
  tcp-request connection reject if !network_allowed
  use_backend my_backend_server
```
The drawback of this method is that TCP load balancer will use these criteria for all requests.
Sometimes it is required that filtering happens only for some specific hostnames.
To match against hostnames it is required to configure allow list on HTTP load Balancer (Nginx Ingress Controller).

#### Allow list on Nginx Ingress Controller
For Nginx Ingress Controller it is possible to configure allow lists based both on hostname and source IP addresses.
See Nginx Ingress Controller `whitelist-source-range` annotation: [https://kubernetes.github.io/ingress-nginx/user-guide/nginx-configuration/annotations/#whitelist-source-range](https://kubernetes.github.io/ingress-nginx/user-guide/nginx-configuration/annotations/#whitelist-source-range).
An example ingress configuration to create allow list based on source IP addresses for particular hostname:
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
In this example, hostname `whitelist.myservicea.foo.org` will be available only from IP address `172.10.0.1` and subnet `10.0.0.0/24`.

### Preserving original HTTP headers

TCP load balancer do not modify HTTP response/request headers. 
Nginx Ingress controller also will not modify **custom** HTTP headers. 
However, Nginx Ingress Controller may modify some well-known headers, as described below:
1. Nginx Ingress Controller always drops some response headers, 
particularly `Date`, `Server`, `X-Pad`, and `X-Accel-...`, see [http://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_hide_header](http://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_hide_header).
2. Nginx Ingress Controller by default sets its own values for `X-Forwarded-*` headers.
If you need to preserve original values for these headers see `use-forwarded-header` config map option: [https://kubernetes.github.io/ingress-nginx/user-guide/nginx-configuration/configmap/#use-forwarded-headers](https://kubernetes.github.io/ingress-nginx/user-guide/nginx-configuration/configmap/#use-forwarded-headers).
This is only required if you have another HTTP LB in front of Nginx Ingress Controller, which sets these headers.
3. Nginx Ingress Controller do not forward `Expect` header. 
This issue could be solved by adding "proxy_set_header" field in NGINX configuration with value "Expect $http_expect". Example `cluster.yaml` configuration:
```
plugins:
  nginx-ingress-controller:
    custom_headers:
      Expect: $http_expect
```
