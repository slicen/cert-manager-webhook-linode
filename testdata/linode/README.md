# Cert-Manager ACME DNS01 Webhook Solver for Linode DNS Manager

## testdata Directory

Copy the example Secret files, replacing $LINODE_TOKEN with your Linode API
token:

```bash
$ export LINODE_TOKEN=$(echo -n "<token>" | base64 -w 0)
$ envsubst < secret.yaml.example > secret.yaml
```
