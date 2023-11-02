# Disable anonymous authentication for `kube-apiserver`

The `--anonymous-auth` option manages anonymous requests to the `kube-apiserver`. By default it enables anonymous requests.

## Prerequisites

* Working Kubernetes cluster
* The following RBAC resources:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: healthz
rules:
- nonResourceURLs: ["/readyz"]
  verbs: ["get"]
- nonResourceURLs: ["/livez"]
  verbs: ["get"]
- nonResourceURLs: ["/healthz"]
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
  name: view
subjects:
- kind: ServiceAccount
  name: healthz
  namespace: kube-system
``` 

## Disabling procedure

1. Add `anonymous-auth: "false"` into the `kubeadm-config` configmap e.g.:

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

Where TOKEN is the result of the following command:

```
kubectl -n kube-system get secret token-healthz -o jsonpath='{.data.token}' | base64 --decode
```

## Limitations

If the `--anonymous-auth` is set to `false` the upgrade and node addition procedures need some changes in workflow. The upgrade procedure needs enabling `anonymous-auth` before the `kubeadm upgrade` run. 

The node addition procedure affects if the control plane node is being added. After new control plane node has successfully added, the [disabling procedure](#disabling-procedure) should be performed on that node.

Besides, disabled anonymous resuests to `kube-apiserver` need changes in monitoring system, if the resources like `healthz`, `readyz`, and `livez` are used in the system. 
