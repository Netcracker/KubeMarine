## TLS termination on Nginx Ingress Controller

This is the default recommended approach to TLS termination on kubetool-installed environments. This approach is applicable when MTLS is not used in kubernetes and all the communications between pods are over plain HTTP.
High-level overview of this approach is shown on the following diagram.

![](/documentation/images/tls-termination-nginx.png)

Here, client creates HTTPS connection to HAProxy TCP Load Balancer, which in turn proxies the traffic to Nginx Ingress Controller without TLS termination.
Nginx Ingress Controller uses default wildcard certificate to authenticate itself to a client and to terminate HTTPS connection.
To support multiple hostnames the certificate could use wildcard SANs.
Nginx Ingress Controller contacts applications using plain HTTP connection.
Thus, using this approach it is very easy to manage only one certificate in one place - TLS traffic will be terminated on nginx ingress controller using default certificate for all application ingresses.

To read more about nginx ingress controller default certificate visit [https://kubernetes.github.io/ingress-nginx/user-guide/tls/#default-ssl-certificate](https://kubernetes.github.io/ingress-nginx/user-guide/tls/#default-ssl-certificate).

**Limitations:**
- Adding new hostname might require to re-issue certificate, if new hostname do not match any previous wildcard SANs.
- Connections form nginx ingress controller to applications are HTTP, i.e. without encryption.
- L7 load balancing options could be customized through "ingress" resources only.

### How to install

To enable TLS termination on Nginx Ingress Controller using default certificate it is required to customize "nginx" plugin with a custom default certificate.
This could be done during installation, for details refer to [nginx plugin installation](/documentation/Installation.md#nginx-ingress-controller).

To enable default certificate on already installed Nginx Ingress Controller, or to renew an existing certificate, 
you could use `certs_renew` maintenance procedure, for details refer to [certificate renew maintenance procedure](/documentation/Maintenance.md#configuring-certificate-renew-procedure-for-nginx-ingress-controller).


**Important:** the default certificate should be issued to wildcard hostnames, so that it could be used for all ingresses.
