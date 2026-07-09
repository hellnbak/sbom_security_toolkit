# Kubernetes and Helm Deployment

Generate the deployment scaffold:

```bash
make k8s-generate
```

The generated Helm chart includes separate web and worker deployments, resource limits, and placeholders for external Postgres, Redis, S3-compatible storage, ingress, and OIDC.

Do not expose cloud mode publicly until authentication, OIDC, secrets, storage encryption, worker limits, and backup controls are configured.
