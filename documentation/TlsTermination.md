## TLS termination on Nginx Ingress Controller

This is the default recommended approach to TLS termination on kubetool-installed environments.

High-level overview of this approach is shown on the following diagram.

![](/documentation/images/tls-termination-nginx.png)

Here, client creates HTTPS connection to HAProxy TCP Load Balancer, which in turn proxies the traffic to Nginx Ingress Controller without termination.
Nginx Ingress Controller uses default wildcard certificate to authenticate itself to a client and to terminate HTTPS connection.
To support multiple hostnames the certificate could use wildcard SANs.
Nginx Ingress Controller contacts applications using HTTP connection.

To read more about nginx ingress controller default certificate visit [https://kubernetes.github.io/ingress-nginx/user-guide/tls/#default-ssl-certificate](https://kubernetes.github.io/ingress-nginx/user-guide/tls/#default-ssl-certificate).

Pros:
+ Easy to manage only one certificate in one place.
+ Used for all ingresses without explicit custom certificates.

Cons:
- Adding new hostname might require to re-issue certificate, if new hostname do not match any previous wildcard SANs.
- Insecure HTTP from nginx ingress controller to pods.
- L7 load balancing could be customized through "ingress" resources only.

### How to install

To enable TLS termination on Nginx Ingress Controller using default certificate it is required to customize "nginx" plugin with a custom default certificate.
This could be done during installation, for details refer to [nginx plugin installation](/documentation/Installation.md#nginx-ingress-controller).

To enable default certificate on already installed Nginx Ingress Controller, or to renew an existing certificate, 
you could use `certs_renew` maintenance procedure, for details refer to [certificate renew maintenance procedure](/documentation/Maintenance.md#configuring-certificate-renew-procedure-for-nginx-ingress-controller).


**Important:** the default certificate should be issues to wildcard hostnames, so that it could be used for all ingresses.