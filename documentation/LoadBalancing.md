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
However, Nginx Ingress Controller may modify some well-known headers, as described below.

First, Nginx Ingress Controller always drops some response headers, 
particularly `Date`, `Server`, `X-Pad`, and `X-Accel-...`, see [http://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_hide_header](http://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_hide_header).

Second, Nginx Ingress Controller by default sets its own values for `X-Forwarded-*` headers.
If you need to preserve original values for these headers see `use-forwarded-header` config map option: [https://kubernetes.github.io/ingress-nginx/user-guide/nginx-configuration/configmap/#use-forwarded-headers](https://kubernetes.github.io/ingress-nginx/user-guide/nginx-configuration/configmap/#use-forwarded-headers).
This is only required if you have another HTTP LB in front of Nginx Ingress Controller, which sets these headers.

Third, Nginx Ingress Controller do not forward `Expect` header. 
This issue could be solved by adding "proxy_set_header" field in NGINX configuration with value "Expect $http_expect".
Example `cluster.yaml` configuration:
```
plugins:
  nginx-ingress-controller:
    custom_headers:
      Expect: $http_expect
```
