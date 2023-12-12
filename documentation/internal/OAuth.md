# Introduction

This document describes how to add `OAuth2` authorization in Kubernetes. It might be used for some HTTP microservice and Kubernetes itself.

# Prerequisites

* Microservice that is deployed in some namespace and works through HTTP.
* Service that leads to the microservice.
* Ingress that makes the microservice externally available.
* `Keycloak` should be installed in the Kubernetes cluster.

# Implementation

## Keycloak Configuration

This part depends on the solution that is used. Basically, the following configurations should be implemented: 

* Keycloak has special realm for the OAuth2 purpose.
* This realm provides objects (users, groups, or/and emails) that can be authenticated and authorized.

Here is an example of Keycloak version 21 configuration for the integration with Active Directory.

### 1. Create realm

![Create realm](/documentation/internal/images-sources/1.jpg)
![Create realm](/documentation/internal/images-sources/2.jpg)

### 2. Add LDAP provider

![Add LDAP provider](/documentation/internal/images-sources/3.jpg)
![Add LDAP provider](/documentation/internal/images-sources/4.jpg)

Set the `Connection URL`, `Bind DN`, and `Users DN` options carefully. Use the `Test connection` and `Test Authentication` buttons to check the settings.

### 3. Create client

![Create client](/documentation/internal/images-sources/5.jpg)
![Create client](/documentation/internal/images-sources/7.jpg)
![Create client](/documentation/internal/images-sources/8.jpg)

`Root URL`, `Valid redirect URIs`, and `Web origins` are very important since they describe endpoints that are covered by authentication.

### 4. Create client scope

![Create client scope](/documentation/internal/images-sources/9.jpg)

### 5. Add mapper

![Add mapper](/documentation/internal/images-sources/10.jpg)

### 6. Add client scope to client

![Add client scope to client](/documentation/internal/images-sources/11.jpg)
![Add client scope to client](/documentation/internal/images-sources/12.jpg)

### 7. Create mapper

![Create mapper](/documentation/internal/images-sources/15.jpg)

`LDAP Groups DN` depends on the Active Directory internal structure.

### 8. Add LDAP filter (Optional)

![Create mapper](/documentation/internal/images-sources/16.jpg)

Add LDAP filter if it is necessary. It decreases the amount of data that should be synchronized.

### 9. Copy client credentials

![Client credentials](/documentation/internal/images-sources/14.jpg)

The `Client secret` is needed for OAuth2-proxy configuration (Keycloak-client-secret). It is located on the `Credentials` tab of a particular `Client`.

## OAuth2-proxy Installation

Parameters:

* Realm-name - The realm name that has been configured for OAuth.
* Keycloak-client-id - The client ID to connect to the Keycloak realm.
* Keycloak-client-secret - The client secret to connect to the Keycloak realm.
* Kubernetes-cluster-fqdn - The FQDN of the Kubernetes cluster.
* Keycloak-fqdn - The Keycloak entry point.
* OAuth2 version - The OAuth2-proxy version (current - 7.4.0).
* Seed-string-for-secure-cookies - The pseudo random string; it might be created by the command: `python -c 'import os,base64; print(base64.b64encode(os.urandom(16)).decode("ascii"))'`. 
* Microservice-name - The desirable microservice name.
* Secret-with-TLS-certificate - The TLS certificate for microservice.

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  labels:
    k8s-app: oauth2-proxy
  name: oauth2-proxy
spec:
  replicas: 1
  selector:
    matchLabels:
      k8s-app: oauth2-proxy
  template:
    metadata:
      labels:
        k8s-app: oauth2-proxy
    spec:
      containers:
      - args:
        - --cookie-domain=.<Kubernetes-cluster-fqdn>
        - --cookie-secure=true
        - --provider=oidc
        - --client-id=<Keycloak-client-id>
        - --client-secret=<Keycloak-client-secret>
        - --oidc-issuer-url=<Keycloak-fqdn>/realms/<Realm-name>
        - --http-address=0.0.0.0:8080
        - --upstream=file:///dev/null
        - --email-domain=*
        - --set-authorization-header=true
        - --ssl-insecure-skip-verify=true
        - --whitelist-domain=.<Kubernetes-cluster-fqdn>
        env:
        - name: OAUTH2_PROXY_COOKIE_SECRET
          value: <Seed-string-for-secure-cookies>
        image: bitnami/oauth2-proxy:<OAuth2 version>
        imagePullPolicy: Always
        name: oauth2-proxy
        ports:
        - containerPort: 8080
          protocol: TCP
apiVersion: v1
kind: Service
metadata:
  labels:
    k8s-app: oauth2-proxy
  name: oauth2-proxy
spec:
  ports:
  - name: http
    port: 8080
    protocol: TCP
    targetPort: 8080
  selector:
    k8s-app: oauth2-proxy
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  annotations:
    kubernetes.io/tls-acme: "true"
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
  name: oauth-proxy
spec:
  ingressClassName: nginx
  rules:
  - host: <Microservice-name>.<Kubernetes-cluster-fqdn>
    http:
      paths:
      - backend:
          service:
            name: oauth2-proxy
            port:
              number: 8080
        path: /oauth2
        pathType: Prefix
  tls:
  - hosts:
    - <Microcervice-name>.<Kubernetes-cluster-fqdn>
    secretName: <Secret-with-TLS-certificate>
```

It is easier to install OAuth2-proxy into the same namespace with the microservice, otherwise it needs to copy the `secret` with the TLS certificate for HTTPS termination, which makes it inconvenient to manage them. The `oauth-proxy` deployment might have some changes that depend on the providers and properties of resources that should be matched during authorization and authentication.

## Ingress Configuration

The Ingress of microservice should be configured too. The annotations should be changed as the following example:

Parameters:

* Kubernetes-cluster-fqdn - The FQDN of the Kubernetes cluster.
* Microservice-name - The desirable microservice name.

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  annotations:
    nginx.ingress.kubernetes.io/auth-signin: https://<Microservice-name>.<Kubernetes-fqdn>/oauth2/start?rd=https://$host$request_uri$is_args$args
    nginx.ingress.kubernetes.io/auth-url: https://<Microservice-name>.<Kubernetes-fqdn>/oauth2/auth
    nginx.ingress.kubernetes.io/configuration-snippet: |
      auth_request_set $token $upstream_http_authorization;
      proxy_set_header Authorization $token;
    nginx.ingress.kubernetes.io/proxy-buffer-size: 16k
...
```

The rest of the specification is not needed to be changed. As a result, there are two ingresses with the same `host` but different `paths` in the namespace. 

For the `Kubernetes-dashboard` service, it is better to create a new ingress since the default ingress is necessary for usual Kubernetes authentication (token, kubeconfig). The Microservice-name in this case should be different from the one that is used in the default 'Kubernetes-dashboard' ingress, but the same as the one that is used in the 'Oauth2-proxy' ingress. The template is as follows:

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: kubernetes-dashboard-ad
  namespace: kubernetes-dashboard
  annotations:
    nginx.ingress.kubernetes.io/auth-signin: https://<Microservice-name>.<Kubernetes-fqdn>/oauth2/start?rd=https://$host$request_uri$is_args$args
    nginx.ingress.kubernetes.io/auth-url: https://<Microservice-name>.<Kubernetes-fqdn>/oauth2/auth
    nginx.ingress.kubernetes.io/backend-protocol: HTTPS
    nginx.ingress.kubernetes.io/configuration-snippet: |
      auth_request_set $token $upstream_http_authorization;
      proxy_set_header Authorization $token;
    nginx.ingress.kubernetes.io/proxy-buffer-size: 16k
spec:
  rules:
  - host: <Microservice-name>.<Kubernetes-cluster-fqdn>
    http:
      paths:
      - pathType: ImplementationSpecific
        backend:
          service:
            name: kubernetes-dashboard
            port:
              number: 443
        path: /
```

## External Authentication for Kubernetes Itself

The following steps should be performed (in addition to the solution that is described above) to configure external authentication and authorization for Kubernetes itself.

## Kube-Apiserver Manifest Changes

`kube-apiserver.yaml` should have the following options in `spec.containers.command`.

Parameters:

* Keycloak-fqdn - The Keycloak entry point.
* Realm-name - The realm name that has been configured for OAuth.
* Path-to-CA-certificate - The path to the CA certificate that is an issuer of `Keycloak` ingress TLS certificate.

```
- --oidc-issuer-url=<Keycloak-fqdn>/realms/<Realm-name>
- --oidc-ca-file=/etc/kubernetes/pki/<Path-to-CA-certificate>
- --oidc-client-id=kubernetes
- --oidc-username-claim=username
- --oidc-username-prefix=-
- --oidc-groups-claim=groups
```

## Role Binding

To get the appropriate permissions to Kubernetes resources, `Users` or `Groups` from an external Identity Provider (for example, Keycloak integrated with Active Directory) should be matched with Kubernetes roles (cluster roles). The user or users in a group in the following example has `edit` permissions in the `default` namespace. The same approach works for Cluster Role Binding.

Parameters:

* Kind - User or Group
* UserName-or-GroupName - Valid user (group) name 

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: external-rb
  namespace: default
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: edit
subjects:
- kind: <Kind>
  name: <UserName-or-GroupName>
```

## Kubeconfig File Generation

Since the automatic kubeconfig file generator [Gangway](https://github.com/vmware-archive/gangway) has been archived, use the kubeconfig file creation procedure that is described in [Kubernetes Authenticating](https://kubernetes.io/docs/reference/access-authn-authz/authentication/#using-kubectl).
