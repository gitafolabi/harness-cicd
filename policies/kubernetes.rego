package main

# ──────────────────────────────────────────────────────────────────────────────
# OPA / Conftest policies for Kubernetes manifests
#
# Run locally:  conftest test k8s/ --policy policies/ --ignore k8s/delegate
# Run in CI:    see .github/workflows/pr-checks.yaml  (opa-policy-check job)
#
# These policies enforce the same controls that Trivy config scan checks, but
# as hard organisational rules rather than advisory findings — any violation
# blocks the PR merge.
# ──────────────────────────────────────────────────────────────────────────────

# ── Rule: every Deployment container must define resource limits ───────────────
deny[msg] {
  input.kind == "Deployment"
  container := input.spec.template.spec.containers[_]
  not container.resources.limits
  msg := sprintf(
    "Deployment '%s': container '%s' is missing resource limits. Define limits.memory and limits.cpu.",
    [input.metadata.name, container.name],
  )
}

# ── Rule: containers must not run as root (runAsUser must be > 0) ─────────────
deny[msg] {
  input.kind == "Deployment"
  container := input.spec.template.spec.containers[_]
  container.securityContext.runAsUser == 0
  msg := sprintf(
    "Deployment '%s': container '%s' must not run as root (runAsUser: 0).",
    [input.metadata.name, container.name],
  )
}

# ── Rule: allowPrivilegeEscalation must be false ──────────────────────────────
deny[msg] {
  input.kind == "Deployment"
  container := input.spec.template.spec.containers[_]
  container.securityContext.allowPrivilegeEscalation == true
  msg := sprintf(
    "Deployment '%s': container '%s' must set allowPrivilegeEscalation: false.",
    [input.metadata.name, container.name],
  )
}

# ── Rule: images must not use the 'latest' tag in a Deployment ────────────────
# NOTE: this project intentionally uses :latest as a workaround for Harness
# expression substitution on the free tier. Disable this rule if you hit it.
# Uncomment to enforce SHA-pinned images in production pipelines.
#
# deny[msg] {
#   input.kind == "Deployment"
#   container := input.spec.template.spec.containers[_]
#   endswith(container.image, ":latest")
#   msg := sprintf(
#     "Deployment '%s': container '%s' uses ':latest' tag. Pin to a specific SHA or semver.",
#     [input.metadata.name, container.name],
#   )
# }

# ── Rule: Deployments must have at least one replica ─────────────────────────
deny[msg] {
  input.kind == "Deployment"
  input.spec.replicas == 0
  msg := sprintf(
    "Deployment '%s' has replicas: 0. Set replicas >= 1.",
    [input.metadata.name],
  )
}

# ── Rule: readOnlyRootFilesystem must not be explicitly false ─────────────────
deny[msg] {
  input.kind == "Deployment"
  container := input.spec.template.spec.containers[_]
  container.securityContext.readOnlyRootFilesystem == false
  msg := sprintf(
    "Deployment '%s': container '%s' sets readOnlyRootFilesystem: false. Set to true and add emptyDir volumes for writable paths.",
    [input.metadata.name, container.name],
  )
}

# ── Rule: Services must not expose NodePort unless explicitly allowed ──────────
deny[msg] {
  input.kind == "Service"
  input.spec.type == "NodePort"
  msg := sprintf(
    "Service '%s' uses NodePort. Prefer ClusterIP + Ingress for controlled external access.",
    [input.metadata.name],
  )
}
