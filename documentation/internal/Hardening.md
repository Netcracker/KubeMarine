# Security Hardening Guide
<!-- TOC -->

- [Overview](#overview)
- [Disable Anonymous Authentication for kube-apiserver](#disable-anonymous-authentication-for-kube-apiserver)
  - [Prerequisites](#prerequisites)
  - [Disabling Procedure](#disabling-procedure)
  - [Limitations](#limitations)
- [Data Encryption in Kubernetes](#data-encryption-in-kubernetes)
  - [Enabling Encryption](#enabling-encryption)
  - [Integration with External KMS](#integration-with-external-kms)
  - [Disabling Encryption](#disabling-encryption)
  - [Maintenance and Operation Features](#maintenance-and-operation-features)
- [Kubelet Server Certificate Approval](#kubelet-server-certificate-approval)
  - [Auto Approval CronJob](#auto-approval-cronjob)
  - [Auto Approval Service](#auto-approval-service)
- [Disabling Auto-Mounting of Tokens for Service Accounts](#disabling-auto-mounting-of-tokens-for-service-accounts)
  - [Disable Auto-Mounting](#disable-auto-mounting)
  - [Create Secret](#create-secret)
  - [Mount the Token Through Secrets](#mount-the-token-through-secrets)
- [Use Strong Cryptographic Ciphers for API Server](#use-strong-cryptographic-ciphers-for-api-server)
  - [Strong Cryptographic Ciphers Suggested by CIS](#strong-cryptographic-ciphers-suggested-by-cis)
  - [Manual Application for Strong Cryptographic Ciphers for API Server on Pre-installed Cluster](#manual-application-for-strong-cryptographic-ciphers-for-api-server-on-pre-installed-cluster)
  - [Automated Application for Strong Cryptographic Ciphers for API Server During New Cluster Installation](#automated-application-for-strong-cryptographic-ciphers-for-api-server-during-new-cluster-installation)
- [Implementing OAuth2 Authorization in Kubernetes](#implementing-oauth2-authorization-in-kubernetes)

<!-- /TOC -->

## Overview

The current document describes the manual steps or procedures that are not covered by the `KubeMarine` code itself, but should be implemented to get a production-ready Kubernetes cluster.

`kube-bench` is a well-known open-source tool to check the Kubernetes cluster against the `CIS Kubernetes Benchmark`. The report is divided on several parts. Each check has its own unique number. The items could be identified by that number.

Useful links:
[kube-bench](https://github.com/aquasecurity/kube-bench)

## Disable Anonymous Authentication for `kube-apiserver`

**Kube-bench Identifier**:

- 1.2.1

The `--anonymous-auth` option manages anonymous requests to the `kube-apiserver`. By default, it enables anonymous requests.

**Note:** If you disable anonymous authentication for `kube-apiserver`,
some Kubemarine maintenance procedures will not work automatically,
and will require manual actions before and after the maintenance.
For more information, refer to [Limitations](#limitations).

### Prerequisites

- A working Kubernetes cluster.
- The following RBAC resources:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: healthz
rules:
- nonResourceURLs: ["/readyz", "/livez"]
  verbs: ["get"]
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: healthz
  namespace: kube-system
---
apiVersion: v1
kind: Secret
metadata:
  annotations:
    kubernetes.io/service-account.name: healthz
  name: token-healthz
  namespace: kube-system
type: kubernetes.io/service-account-token
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: healthz
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: healthz
subjects:
- kind: ServiceAccount
  name: healthz
  namespace: kube-system
```

**Note:** ClusterRole and ClusterRoleBinding are not required
if you have `system:discovery` or `system:public-info-viewer` ClusterRoleBindings installed on the cluster (default).
Though, such role bindings provide wider permissions than those that are necessary for the probes.

### Disabling Procedure

1. Add `anonymous-auth: "false"` into the `kubeadm-config` configmap. For example:

    ```yaml
    apiVersion: v1
    data:
      ClusterConfiguration: |
        apiServer:
          certSANs:
          - 192.168.56.106
          - ubuntu
          extraArgs:
            anonymous-auth: "false"
    ...
    ```

2. Change the `kube-apiserver` manifest on each control plane nodes one by one according to the following example:

    ```yaml
    apiVersion: v1
    kind: Pod
    metadata:
    ...
      name: kube-apiserver
      namespace: kube-system
    spec:
      containers:
      - command:
        - kube-apiserver
        - --anonymous-auth=false
    ...
        livenessProbe:
          failureThreshold: 8
          httpGet:
            host: 192.168.56.106
            path: /livez
            port: 6443
            scheme: HTTPS
            httpHeaders:
              - name: Authorization
                value: Bearer <TOKEN>
    ...
        readinessProbe:
          failureThreshold: 3
          httpGet:
            host: 192.168.56.106
            path: /readyz
            port: 6443
            scheme: HTTPS
            httpHeaders:
              - name: Authorization
                value: Bearer <TOKEN>
    ...
        startupProbe:
          failureThreshold: 24
          httpGet:
            host: 192.168.56.106
            path: /livez
            port: 6443
            scheme: HTTPS
            httpHeaders:
              - name: Authorization
                value: Bearer <TOKEN>
    ...
    ```

Where, TOKEN is the result of the following command:

```console
kubectl -n kube-system get secret token-healthz -o jsonpath='{.data.token}' | base64 --decode
```

### Limitations

If the `--anonymous-auth` is set to "false", the upgrade and node addition procedures need some changes in the workflow.
Both procedures needs enabling `anonymous-auth` on all existing control plane nodes before the `kubeadm` run.

After the procedure is performed, the [Disabling Procedure](#disabling-procedure) should be performed on all control plane nodes.

Besides, disabled anonymous requests to `kube-apiserver` need changes in the monitoring system, if the resources like `healthz`, `readyz`, and `livez` are used in the system.

## Data Encryption in Kubernetes

**Kube-bench Identifier**:

- 1.2.29
- 1.2.30

The following section describes the Kubernetes cluster capabilities to store and manipulate the encrypted data.

### Enabling Encryption

ETCD as a Kubernetes cluster storage can interact with the encrypted data. The encryption/decryption procedures are the part of the `kube-apiserver` functionality.

An example of the `EncryptionConfiguration` file is as follows:

```yaml
apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
  - resources:
      - secrets
      - configmaps
    providers:
      - aesgcm:
          keys:
            - name: key1
              secret: c2VjcmV0IGlzIHNlY3VyZQ==
            - name: key2
              secret: dGhpcyBpcyBwYXNzd29yZA==
      - aescbc:
          keys:
            - name: key1
              secret: c2VjcmV0IGlzIHNlY3VyZQ==
            - name: key2
              secret: dGhpcyBpcyBwYXNzd29yZA==
      - secretbox:
          keys:
            - name: key1
              secret: YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=
      - identity: {}
```

It should be created preliminarily and placed in the `/etc/kubernetes/enc/` directory.

The next step is to enable the encryption settings in `kubeadm-config`:

```yaml
data:
  ClusterConfiguration: |
    apiServer:
      ...
      extraArgs:
        ...
        encryption-provider-config: /etc/kubernetes/enc/enc.yaml
      extraVolumes:
      ...
      - hostPath: /etc/kubernetes/enc
        mountPath: /etc/kubernetes/enc
        name: enc
        pathType: DirectoryOrCreate
```

There is an `--encryption-provider-config` option that points to the `EncryptionConfiguration` file location. The `kube-apiserver` should have the following parts in the manifest yaml:

```yaml
...
spec:
  containers:
  - command:
    - kube-apiserver
     ...
    - --encryption-provider-config=/etc/kubernetes/enc/enc.yaml
      ...
    volumeMounts:
    - name: enc
      mountPath: /etc/kubernetes/enc
      readonly: true
       ...
  volumes:
  - name: enc
    hostPath:
      path: /etc/kubernetes/enc
      type: DirectoryOrCreate
```

In the above case, `secrets` and `configmaps` are encrypted on the first key of the `aesgcm` provider, but the previously encrypted `secrets` and `configmaps` are decrypted on any keys of any providers that are matched. This approach allows to change both encryption providers and keys during the operation. The keys should be random strings in base64 encoding. `identity` is the default provider that does not provide any encryption at all.
For more information, refer to [https://kubernetes.io/docs/tasks/administer-cluster/encrypt-data/](https://kubernetes.io/docs/tasks/administer-cluster/encrypt-data/).

As per the CIS benchmark (kube-bench checks), the `aesgcm` provider for encryption is not recognized as an appropriate provider. To fulfil this requirement, we have to configure `aescbc`, `secretxbox`, or `kms` as an encryption provider.

### Integration with External KMS

There is an encryption provider `kms` that allows using an external `Key Management Service` for the key storage, therefore the keys are not stored in the `EncryptionConfiguration` file, which is more secure. The `kms` provider needs to deploy a KMS plugin for further use.
The `Trousseau` KMS plugin is an example. It works through a unix socket, therefore `Trousseau` pods must be run on the same nodes as `kube-apiserver`. In case of using a KMS provider, the `EncryptionConfiguration` is as follows (`Vault` is a KMS):

```yaml
apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
  - resources:
      - secrets
      - configmaps
    providers:
      - kms:
          name: vaultprovider
          endpoint: unix:///opt/vault-kms/vaultkms.socket
          cachesize: 100
          timeout: 3s
      - identity: {}
```

Also, the unix socket must be available for `kube-apiserver`:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: kube-apiserver
  namespace: kube-system
spec:
  containers:
  - command:
    volumeMounts:
    - mountPath: /opt/vault-kms/vaultkms.socket
      name: vault-kms
       ...
  volumes:
  - hostPath:
      path: /opt/vault-kms/vaultkms.socket
      type: Socket
    name: vault-kms
```

The environment variable `VAULT_ADDR` matches the address of the `Vault` service and `--listen-addr` argument points to the KMS plugin unix socket in the following example:

```yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: vault-kms-provider
  namespace: kube-system
    ...
spec:
  template:
    spec:
      initContainers:
        - name: vault-agent
          image: vault
          securityContext:
            privileged: true
          args:
            - agent
            - -config=/etc/vault/vault-agent-config.hcl
            - -log-level=debug
          env:
            - name: VAULT_ADDR
              value: http://vault-adress:8200
               ...
      containers:
        - name: vault-kms-provider
          image: ghcr.io/ondat/trousseau:v1.1.3
          imagePullPolicy: Always
          args:
            - -v=5
            - --config-file-path=/opt/trousseau/config.yaml
            - --listen-addr=unix:///opt/vault-kms/vaultkms.socket
            - --zap-encoder=json
            - --v=3
```

For more information, refer to:

- [https://kubernetes.io/docs/tasks/administer-cluster/kms-provider/](https://kubernetes.io/docs/tasks/administer-cluster/kms-provider/)
- [https://github.com/ondat/trousseau/wiki/Trousseau-Deployment](https://github.com/ondat/trousseau/wiki/Trousseau-Deployment)

### Disabling Encryption

The first step for disabling encryption is to make the `identity` provider default for encryption. The enabling of `EncryptionConfiguration` should be similar to the following example:

```yaml
apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
  - resources:
      - secrets
      - configmaps
    providers:
      - identity: {}
      - aesgcm:
          keys:
            - name: key1
              secret: c2VjcmV0IGlzIHNlY3VyZQ==
            - name: key2
              secret: dGhpcyBpcyBwYXNzd29yZA==
      - aescbc:
          keys:
            - name: key1
              secret: c2VjcmV0IGlzIHNlY3VyZQ==
            - name: key2
              secret: dGhpcyBpcyBwYXNzd29yZA==
      - secretbox:
          keys:
            - name: key1
              secret: YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=
```

The next step is to replace all resources that were previously encrypted (for example, `secrets`):

```console
# kubectl get secrets --all-namespaces -o json | kubectl replace -f -
```

It is then possible to remove the encryption settings from the `kubeadm-config` configmap and `kube-apiserver` manifest.

### Maintenance and Operation Features

- Since the `/etc/kubernetes/enc/enc.yaml` file has keys, access to the file must be restricted. For instance:
  
```console
# chmod 0700 /etc/kubernetes/enc/
```

- The proper way for using encryption is to rotate the keys. The rotation procedure of the keys should take into consideration the fact that the `EncryptionConfiguration` file must be equal on each `control-plane` node. During the keys' rotation procedure, some operation of getting the encrypted resources may be unsuccessful.
- The `kube-apiserver` has an `--encryption-provider-config-automatic-reload` option that allows to apply a new `EncryptionConfiguration` without `kube-apiserver` reload.
- ETCD restore procedures should take into consideration the keys' rotation, otherwise some data may be unavailable due to keys that were used for the encryption and is not available after restoration. The backup procedure may include an additional step that renews all encrypted data before the ETCD backup. This approach decreases the security level for the data in ETCD backup, but it prevents any inconvenience in the future. Another option is not to delete the keys from `env.yml` even if they are not used for encryption/decryption anymore.
- External services that interact with ETCD may stop working due to encryption enabling.

## Kubelet Server Certificate Approval

**Kube-bench Identifier**:

- 1.2.5

The `kubelet` server certificate is self-signed by default, and is usually stored in the `/var/lib/kubelet/pki/kubelet.crt` file. To avoid using the self-signed `kubelet` server certificate, alter the `cluster.yaml` file in the following way:

```yaml
...
services:
  kubeadm_kubelet:
    serverTLSBootstrap: true
    rotateCertificates: true
  kubeadm:
    apiServer:
      extraArgs:
        kubelet-certificate-authority: /etc/kubernetes/pki/ca.crt
...
```

These settings enforce `kubelet` on each node of the cluster to request certificate approval (for `kubelet` server part) from the default Kubernetes CA and rotate certificate in the future. The `kube-apiserver` machinery does not approve certificate requests for `kubelet` automatically. They can be approved manually by the following commands. Use the following command to get the list of certificate requests:

```console
# kubectl get csr
NAME        AGE     SIGNERNAME                          REQUESTOR                 REQUESTEDDURATION    CONDITION
csr-2z6rv   12m     kubernetes.io/kubelet-serving       system:node:nodename-1    <none>               Pending
csr-424qg   89m     kubernetes.io/kubelet-serving       system:node:nodename-2    <none>               Pending
```

Use the following command to approve a particular request:

```console
kubectl certificate approve csr-424qg
```

These commands might be automated in several ways.

### Auto Approval CronJob

Generally, `CronJob` runs the approval command above for every CSR according to some schedule.

### Auto Approval Service

It is possible to install the kubelet-csr-approver service. For more information, refer to [kubelet-csr-approver](https://github.com/postfinance/kubelet-csr-approver). This service approves the CSR automatically when a CSR is created according to several settings. It is better to restrict nodes' IP addresses (`providerIpPrefixes` option) and FQDN templates (providerRegex). For more information, refer to the official documentation.

## Disabling Auto-Mounting of Tokens for Service Accounts

**Kube-bench Identifier**:

- 5.1.5

Create explicit service accounts wherever a Kubernetes workload requires specific access to the Kubernetes API server.
Modify the configuration of each default service account to include this value `automountServiceAccountToken: false`

To disable the auto-mounting of service account tokens, create secrets associated with a particular service account and mount that secret as a volume to the pod's specification wherever necessary.

To achieve this, implement the following procedure.

### Disable Auto-Mounting

To disable auto-mounting of a token, add `automountServiceAccountToken: false` flag to the service account properties as shown below.

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: ingress-nginx
  namespace: ingress-nginx
automountServiceAccountToken: false
...
```

### Create Secret

Create a new Kubernetes secret of type `kubernetes.io/service-account-token` as follows.

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: ingress-nginx-token
  namespace: ingress-nginx
  annotations:
    kubernetes.io/service-account.name: ingress-nginx
type: kubernetes.io/service-account-token
```

### Mount the Token Through Secrets

Edit the POD specification and mount the secret as a volume to the pod as follows.

```yaml
...
volumeMounts:
  - name: ingress-nginx-token
    mountPath: /var/run/secrets/kubernetes.io/serviceaccount

...

volumes:
  - name: ingress-nginx-token
    secret:
      secretName: ingress-nginx-token
...
```

After this, restart the pod to reflect the changes and verify that the secret is mounted to the pod at the specified mount point.

## Use Strong Cryptographic Ciphers for API Server

**Kube-bench Identifier**:

- 1.2.31

### Strong Cryptographic Ciphers Suggested by CIS

- TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
- TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
- TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305
- TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
- TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305
- TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384

### Manual Application for Strong Cryptographic Ciphers for API Server on Pre-installed Cluster

Edit the API server pod specification file `/etc/kubernetes/manifests/kube-apiserver.yaml` on the control all plane nodes and add below parameter to the API server arguments

```yaml
spec:
  containers:
  - command:
    - kube-apiserver
    ...
    - --tls-cipher-suites=TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_CHACHA
    ...
```

Save the file with above mentioned changes and the kube-apiserver pods will be restarted.
Restart the pods manually in case automatic restart doesn't happen in order to apply the changes in the cluster.

Also make sure to update `kubeadm-config` configmap in kube-system namespace to store these changes. Elseon running any of the mantenance procedue, these changes would be lost.

`kubectl edit cm kubeadm-config -n kube-system`

### Automated Application for Strong Cryptographic Ciphers for API Server During New Cluster Installation

For applying Strong Cryptographic Ciphers for API server at the time of installation of cluster itself, then it can be done through Kubemarine.
To do so, follow the below procedure:

- Add cryptographic ciphers suites to the kubeadm config as extra arguments for API server in `cluster.yaml` file

```yaml
services:
  kubeadm:
    kubernetesVersion: v1.28.3
    ...
    apiServer:
      extraArgs:
        tls-cipher-suites: TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
    ...
```

- Run Kubemarine install procedure using above config added to `cluster.yaml` file

## Implementing OAuth2 Authorization in Kubernetes

**Kube-bench Identifier**:

- 3.1.2

Service account token authentication should not be used for users.

Alternative mechanisms provided by Kubernetes such as the use of OIDC should be implemented in place of service account tokens.

Here is a list of available tools that can be used for Identity and Access Management in Kubernetes cluster.

1. **Dex** - A lightweight OIDC provider server that can be configured to work with various identity providers. More information about this tool can be found on https://github.com/dexidp/dex. The documentation for configuring Dex with your k8s cluster can be found at https://dexidp.io/docs/kubernetes/.
2. **OpenUnison** - An open-source OIDC provider, focusing on security and ease of use. More information about this tool can be found at https://github.com/OpenUnison/openunison-k8s-idm-oidc. The documentation for configuring OpenUnison with your k8s cluster can be found at https://openunison.github.io/. 
3. **Keycloak** - An open source identity and access management solution. More information about this tool can be found at https://www.keycloak.org. The documentation for configuring Keycloak with your k8s cluster can be found at https://medium.com/elmo-software/kubernetes-authenticating-to-your-cluster-using-keycloak-eba81710f49b. 
4. **JWT Authenticator** - Kubernetes itself offers a built-in "JWT Authenticator". This authenticator validates tokens issued by an OIDC provider based on the configured issuer and retrieves the public key for verification through OIDC discovery. More information about this tool can be found at https://kubernetes.io/docs/reference/access-authn-authz/authentication/. 
