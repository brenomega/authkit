# Unsupported Kubernetes example

These manifests are isolated reference material, not a v0.1 production or release path. They do not include PostgreSQL, Redis, TLS ingress, external secret management, operator email templates, runtime/retention database-role provisioning, provider proof, restore, chaos, autoscaling, or multi-node correctness evidence. `authkit:local` must be loaded explicitly into a disposable cluster.

Do not infer support or capacity from successful YAML validation. The only release-gated topology is `deploy/golden`; promoting Kubernetes requires dedicated real-dependency tests, security review, operational documentation, and independent proof.
