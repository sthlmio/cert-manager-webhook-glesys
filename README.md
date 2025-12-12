# cert-manager webhook for Glesys DNS

cert-manager webhook for Glesys DNS is an ACME [webhook](https://cert-manager.io/docs/configuration/acme/dns01/webhook/) for [cert-manager](https://cert-manager.io/) allowing users to use [Glesys DNS](https://glesys.se/tjanster/domaner) for DNS01 challenges.

## Getting started

### Prerequisites

- A [Glesys API key](https://cloud.glesys.com/api-access)
- A valid domain configured on Glesys DNS
- A Kubernetes cluster (v1.32+ recommended)
- cert-manager [deployed](https://cert-manager.io/docs/in7stallation/) on the cluster

### Install

```
helm install cert-manager-webhook-glesys \
  oci://ghcr.io/sthlmio/cert-manager-webhook-glesys \
  --version 1.2.0 \
  --set groupName=acme.sthlm.io \
  --set apiKeySecretName=glesys-api-secret
```

### How to use it

### Secret

Containing the Glesys API key

```yaml
apiVersion: v1
kind: Secret
type: Opaque
metadata:
  name: glesys-api-secret
data:
  key: <your-glesys-secret-key-base64>
```

### ClusterIssuer or Issuer CRD

Both ClusterIssuer and Issuer will work (DNS01)

```yaml
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: glesys-dns01-issuer
spec:
  acme:
    email: <my-user@example.com>
    server: https://acme-v02.api.letsencrypt.org/directory
    privateKeySecretRef:
      name: glesys-issuer-account-key
    solvers:
      - dns01:
          webhook:
            groupName: acme.sthlm.io # Change this to e.g acme.mycompany.com
            solverName: glesys
            config:
              project: <glesys project id>
              apiURL: https://api.glesys.com
              apiKeySecretRef:
                name: glesys-api-secret
                key: key
```
