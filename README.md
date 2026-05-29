# Boutique Microservices – Harness CI/CD Reference Implementation

A production-grade CI/CD reference for a seven-service Node.js microservices app deployed to Kubernetes. Covers Harness CI/CD, GitHub Actions, ArgoCD GitOps, Terraform, secrets management, security scanning, and Kubernetes hardening. Connector examples are provided for AKS, EKS, GKE, Rancher, OpenShift, vanilla Kubernetes, and kind.

---

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [Repository Structure](#2-repository-structure)
3. [Prerequisites](#3-prerequisites)
4. [Infrastructure Setup](#4-infrastructure-setup)
5. [Harness Setup](#5-harness-setup)
6. [Pipeline Scenarios](#6-pipeline-scenarios)
7. [Security Gates](#7-security-gates)
8. [Kubernetes Hardening](#8-kubernetes-hardening)
9. [Secrets Management](#9-secrets-management)
10. [GitOps with ArgoCD](#10-gitops-with-argocd)
11. [Deployment Strategies](#11-deployment-strategies)
12. [Observability](#12-observability)
13. [DORA Metrics](#13-dora-metrics)
14. [Adapting for Other Kubernetes Providers](#14-adapting-for-other-kubernetes-providers)

---

## 1. Architecture Overview

```
Developer push → GitHub PR
                    │
                    ▼
          ┌─────────────────────┐
          │   PR Gate (GHA)     │
          │  • Trivy config     │
          │  • OPA/Conftest     │
          │  • yamllint         │
          │  • hadolint         │
          └─────────┬───────────┘
                    │ merge to main
                    ▼
          ┌─────────────────────┐
          │   CI (GHA)          │
          │  • Docker build     │
          │  • Trivy image scan │
          │  • SBOM (Syft)      │
          │  • Push to Hub      │
          └─────────┬───────────┘
                    │ Harness REST API
                    ▼
          ┌─────────────────────┐
          │   CD (Harness)      │
          │  • Approval gate    │
          │  • Rolling deploy   │
          │  • Auto-rollback    │
          └─────────┬───────────┘
                    │
                    ▼
          Kubernetes – boutique ns
          (AKS / EKS / GKE / Rancher
           OpenShift / kind / vanilla)
```

**Three-tool architecture — each tool does what it does best:**

| Tool | Role | Why |
|---|---|---|
| GitHub Actions | CI: build, scan, push, PR gates | Fast, developer-native, excellent Docker layer cache |
| Harness | CD: approvals, rolling deploy, rollback | Governance, audit trail, deployment verification |
| ArgoCD | Platform GitOps | Continuous reconciliation for infra/platform apps |

---

## 2. Repository Structure

```
harness-cicd/
├── .github/
│   └── workflows/
│       ├── ci.yaml               # CI: build → scan → SBOM → push → trigger Harness
│       └── pr-checks.yaml        # PR gate: Trivy + OPA + yamllint + hadolint
│
├── .harness/
│   ├── pipeline.yaml                    # Scenario B: GHA CI + Harness CD (active)
│   ├── pipeline-harness-ci.yaml         # Scenario A: full Harness CI+CD
│   ├── pipeline-canary.yaml             # Canary deploy example (gateway)
│   ├── connectors/
│   │   ├── github.yaml                  # GitHub connector
│   │   ├── dockerhub.yaml               # Docker Hub connector
│   │   └── k8s-aks.yaml                 # AKS cluster connector (InheritFromDelegate)
│   ├── environments/
│   │   └── production.yaml              # boutique_production environment
│   ├── infrastructure/
│   │   └── aks-boutique.yaml            # AKS boutique namespace infra definition
│   ├── services/
│   │   ├── auth.yaml
│   │   ├── gateway.yaml
│   │   ├── orders.yaml
│   │   ├── product-service.yaml
│   │   ├── user-service.yaml
│   │   ├── notification-service.yaml
│   │   └── frontend.yaml
│   ├── templates/
│   │   └── cd-rolling-deploy-stage.yaml # Reusable CD stage template
│   └── triggers/
│       └── on-push-main.yaml            # Webhook trigger (alternative to GHA API call)
│
├── k8s/
│   ├── auth.yaml
│   ├── gateway.yaml
│   ├── orders.yaml
│   ├── product-service.yaml
│   ├── user-service.yaml
│   ├── notification-service.yaml
│   ├── frontend.yaml
│   ├── ingress.yaml
│   └── delegate/                        # Harness Delegate manifests
│
├── policies/
│   └── kubernetes.rego                  # OPA policies (resource limits, non-root, etc.)
│
└── projects/
    └── boutique-microservices/
        ├── backend/services/            # Node.js microservices source + Dockerfiles
        └── frontend/                    # React frontend source + Dockerfile
```

---

## 3. Prerequisites

| Requirement | Notes |
|---|---|
| Kubernetes cluster | 2+ nodes, Kubernetes 1.25+. Any provider — AKS, EKS, GKE, Rancher, kind, etc. See [Section 14](#14-adapting-for-other-kubernetes-providers) |
| Harness SaaS account | Free tier works. app.harness.io |
| Container registry | Docker Hub used here; swap `dockerhub_boutique` connector for ECR, GCR, ACR, etc. |
| Secrets backend | Azure Key Vault used here with ESO; AWS Secrets Manager, GCP Secret Manager, or HashiCorp Vault are drop-in alternatives |
| `kubectl` + `helm` | To install the Harness Delegate into your cluster |
| `gh` CLI | For branch protection setup |

---

## 4. Infrastructure Setup

### Kubernetes cluster with Terraform

Any Kubernetes distribution works with this repo — swap the connector file for your provider (see [Section 14](#14-adapting-for-other-kubernetes-providers)). The reference cluster used here is AKS, provisioned with Terraform at:
[github.com/gitafolabi/aks-app/tree/main/infrastructure](https://github.com/gitafolabi/aks-app/tree/main/infrastructure)

Key Terraform patterns used:

```hcl
# State in Azure Storage (remote backend with locking)
terraform {
  backend "azurerm" {
    resource_group_name  = "tfstate-rg"
    storage_account_name = "tfstateboutique"
    container_name       = "tfstate"
    key                  = "aks-boutique.tfstate"
  }
}
```

**Why remote state with locking?** Prevents concurrent `terraform apply` runs from corrupting state. The Azure blob lease is the lock — only one pipeline can apply at a time.

### Harness Delegate (Helm)

The Delegate is the agent Harness uses to reach your cluster. Install it once; all pipelines route through it.

```bash
helm repo add harness https://app.harness.io/storage/harness-download/harness-helm-charts/
helm repo update

helm install helm-delegate harness/harness-delegate \
  --namespace harness-delegate-ng --create-namespace \
  --set delegateName=helm-delegate \
  --set accountId=<YOUR_ACCOUNT_ID> \
  --set delegateToken=<YOUR_DELEGATE_TOKEN> \
  --set managerEndpoint=https://app.harness.io
```

**How it works:** The Delegate pod runs in your cluster with a ServiceAccount that has `cluster-admin`. It opens an outbound HTTPS connection to Harness SaaS — your cluster is never directly exposed. All pipeline tasks (Git clone, image push, K8s apply) are executed by the Delegate.

**Verify:** In Harness UI → Account Settings → Delegates → `helm-delegate` should show "Connected".

---

## 5. Harness Setup

### Import order (create dependencies before referencing them)

1. **Connectors** — GitHub, Docker Hub, Kubernetes  
2. **Secrets** — `github_pat`, `dockerhub_password` in Harness Secrets Manager  
3. **Environment** — `boutique_production`  
4. **Infrastructure Definition** — `aks_boutique` (inside the environment)  
5. **Services** — all 7 (reference the connectors)  
6. **Pipeline** — references services, environment, infrastructure  

### Connectors

All connector YAML files are in `.harness/connectors/`. Import via:  
Harness UI → Project Settings → Connectors → `+New` → paste YAML.

**Key concept — `delegateSelector: helm-delegate`:**  
The K8s connector uses `credential.type: InheritFromDelegate` — it inherits the Delegate's in-cluster ServiceAccount instead of a static kubeconfig. This means no credentials to rotate.

### Services

Each service in `.harness/services/` defines:
- **Manifest source** — Git (GitHub connector, `harness-cicd` repo, specific path in `k8s/`)
- **Artifact source** — Docker Hub image with `tag: <+input>` (overridden at pipeline runtime)

**Important — `repoName: harness-cicd`:**  
The GitHub connector uses an Account URL (`https://github.com/gitafolabi`), so `repoName` must be set on every manifest store spec. Without it, Harness throws `repo name cannot be empty for Account URL type`.

### Environment & Infrastructure Definition

- Environment: `boutique_production` — represents the production AKS cluster
- Infrastructure: `aks_boutique` — namespace `boutique`, release name `boutique`

**Why `releaseName: boutique` (not `boutique-<+infra.identifier>`)?**  
Kubernetes Helm release names cannot contain underscores. `aks_boutique` contains an underscore, so using the expression would generate `boutique-aks_boutique` — an invalid name. Hard-code a clean release name.

### Approval User Group

Create a project-level user group for approvals:  
Harness UI → Project Settings → User Groups → `+New Group` → name `Boutique Approvers`, identifier `Boutique_Approvers` → assign Project Admin role → add your user.

**Why project-level, not account-level?**  
The pipeline is scoped to project `BoutiqueApp`. Account-level groups (`account.All Account Users`) have a different scope and the approval step rejects them with `User not authorized`.

**`disallowPipelineExecutor: false`:** The person who triggered the pipeline can also approve. Set to `true` in real production for separation of duties (SOC 2 requirement).

### GitHub Repository Secrets

Add these to the `harness-cicd` repo (Settings → Secrets → Actions):

| Secret | Value |
|---|---|
| `DOCKERHUB_USERNAME` | Your Docker Hub username |
| `DOCKERHUB_PASSWORD` | Docker Hub access token |
| `HARNESS_ACCOUNT_ID` | From app.harness.io URL or Account Settings |
| `HARNESS_API_KEY` | Harness UI → Account Settings → API Keys → +New |

---

## 6. Pipeline Scenarios

### Scenario B — GitHub Actions CI + Harness CD (`.harness/pipeline.yaml`)

**This is the active production pipeline.**

```
GHA (ci.yaml)                       Harness (pipeline.yaml)
─────────────────────────────       ────────────────────────────────────
matrix build (7 services)    →      imageTag variable (git SHA)
  └─ docker build                   approval_prod stage
  └─ trivy image scan               parallel CD stages (5 services)
  └─ syft SBOM                      cd_gateway stage
  └─ docker push (SHA + latest)     cd_frontend stage
  └─ curl Harness API  ─────────────►
```

**Why this split?**
- GHA: fast, parallel matrix builds with layer caching (`type=gha`) — 7 images in ~4 min
- Harness: governance layer — approval gate, rollback, audit trail, RBAC

**Triggering Harness from GHA:**

```yaml
curl -X POST \
  "https://app.harness.io/gateway/pipeline/api/pipeline/execute/boutique_full_cicd?accountIdentifier=...&orgIdentifier=default&projectIdentifier=BoutiqueApp" \
  -H "x-api-key: ${{ secrets.HARNESS_API_KEY }}" \
  -H "Content-Type: application/yaml" \
  --data "pipeline:
  identifier: boutique_full_cicd
  variables:
    - name: imageTag
      type: String
      value: ${{ github.sha }}"
```

The `imageTag` variable flows through every CD stage as `<+pipeline.variables.imageTag>`, ensuring the exact SHA built by GHA is what gets deployed.

---

### Scenario A — Full Harness CI+CD (`.harness/pipeline-harness-ci.yaml`)

**For teams that want a single-platform story entirely within Harness.**

```
Harness pipeline
  CI Stage 1: auth  (Kaniko on KubernetesDirect)
  CI Stage 2: gateway
  CI Stage 3: orders
  CI Stage 4: product-service
  CI Stage 5: user-service
  CI Stage 6: notification-service
  CI Stage 7: frontend
  Approval Stage
  CD Stages (parallel): auth, product, orders, user, notification
  CD Stage: gateway
  CD Stage: frontend
```

**Why sequential CI stages, not parallel?**  
On a 2-node AKS cluster, 7 parallel Kaniko builds exceed CPU limits — pods get stuck in `Pending` with `0/2 Insufficient cpu`. Sequential builds use ~500m CPU each, well within per-node capacity.

**Why KubernetesDirect, not Harness Cloud?**  
Harness Cloud (hosted runners) requires a credit card for verification even on the free tier. KubernetesDirect uses your own AKS cluster as the build infrastructure — no additional cost or verification.

**`tag: latest` in CD serviceInputs:**  
When retrying from the Approval stage, the CI stages don't re-run. The `<+pipeline.sequenceId>` tag from the original CI run no longer exists on the retry's sequenceId. Using `latest` ensures the most recently built image is always pullable.

---

### Canary Deploy (`.harness/pipeline-canary.yaml`)

Demonstrates progressive delivery for the API Gateway:

```
Phase 1 – Canary (20%)
  K8sCanaryDeploy → deploys 20% of pods to new version
  HarnessApproval → reviewer validates error rate + latency in Grafana
  [or replace approval with Harness SRM Continuous Verification]

Phase 2 – Primary (100%)
  K8sRollingDeploy → promotes new version to all pods
```

**When to use canary vs rolling:**
- **Rolling** — safe default; gradual pod replacement, single-version traffic at any point
- **Canary** — real-traffic validation at small scale; requires observability to compare canary vs primary metrics
- **Blue-green** — instant traffic switch; zero mixed-version period; costs 2x compute during switch

**Evolving the canary:** Replace the `HarnessApproval` step with a Harness SRM `ContinuousVerification` step. It queries Prometheus/Datadog for the canary pod metrics vs the primary baseline and auto-promotes or auto-rolls back based on your configured threshold — no human required in the approval loop.

---

### Reusable CD Template (`.harness/templates/cd-rolling-deploy-stage.yaml`)

Defines the rolling deploy + rollback pattern once. Any pipeline references it with `templateRef: cd_rolling_deploy_stage` and provides only `serviceRef`, `environmentRef`, and `infrastructureDefinitions` as inputs.

**Why templates matter at scale:**  
Without a template, every microservice pipeline duplicates the K8sRollingDeploy + K8sRollingRollback + StageRollback failure strategy. If you need to change the deploy timeout from 10m to 15m, you edit one template instead of seven pipelines.

---

## 7. Security Gates

### PR Gate (`.github/workflows/pr-checks.yaml`)

Four parallel jobs run on every PR to `main`. All must pass before merge is allowed (enforced via GitHub branch protection).

```
┌────────────────────────────┐  ┌──────────────────────────┐
│  OPA / Conftest            │  │  yamllint                 │
│  conftest test k8s/        │  │  .harness/ YAML files     │
│  --policy policies/        │  │  max line-length: 200     │
│  skips: delegate, argo     │  │                           │
└────────────────────────────┘  └──────────────────────────┘
┌────────────────────────────┐
│  hadolint                  │
│  all 7 Dockerfiles         │
│  failure-threshold: error  │
└────────────────────────────┘
```

Trivy config scan (K8s YAML misconfigs) was intentionally removed from the PR gate — OPA/Conftest covers the same manifest quality checks with custom rules, and Trivy image scanning happens in the CI workflow after build. Running both in the PR gate was redundant and added ~30s of latency per PR.

**OPA/Conftest vs Trivy — what's the difference?**
- Trivy image scan (CI) — scans built container images for known CVEs in OS packages and language libraries. Runs after `docker build`.
- OPA/Conftest (PR gate) — enforces your team's specific Kubernetes standards as code (resource limits, non-root, readOnlyRootFilesystem). Runs on YAML files before merge. You write the rules.

### CI Image Scan (`.github/workflows/ci.yaml`)

After each image is built (but before push), Trivy scans it for CVEs:

```yaml
- name: Trivy image scan
  uses: aquasecurity/trivy-action@master
  with:
    image-ref: avurlerby/auth:${{ github.sha }}
    exit-code: "1"
    ignore-unfixed: true    # skip CVEs with no patch available
    vuln-type: os,library
    severity: CRITICAL      # block only on CRITICAL; HIGH is reported but not blocking
```

`ignore-unfixed: true` — only fails on CVEs that have a fix available (i.e., a newer package version exists). This removes noise from vulnerabilities you can't act on.

### SBOM Generation

After each image scan, Syft generates a Software Bill of Materials:

```yaml
- name: Generate SBOM (Syft)
  uses: anchore/sbom-action@v0
  with:
    image: avurlerby/auth:${{ github.sha }}
    format: cyclonedx-json
    output-file: sbom-auth-${{ github.sha }}.json
    upload-artifact: true
```

The SBOM is uploaded as a GitHub Actions artifact, retained per run. When a new CVE is disclosed (e.g., Log4Shell), query the SBOM archive to instantly know which of your services are affected — rather than rescanning all images.

**Compliance value:** The NTIA minimum elements, EU Cyber Resilience Act, and US Executive Order 14028 all require SBOMs for software supply chain transparency.

### OPA Policies (`policies/kubernetes.rego`)

Run locally before committing:

```bash
# Install conftest
brew install conftest

# Test all manifests
conftest test k8s/ --policy policies/ --ignore k8s/delegate

# Test a single file
conftest test k8s/frontend.yaml --policy policies/
```

Current policies enforced:
- Every Deployment container must define `resources.limits`
- No container may run as `runAsUser: 0` (root)
- `allowPrivilegeEscalation` must not be `true`
- `readOnlyRootFilesystem` must not be explicitly `false`
- Services must not use `NodePort`
- Deployments must have `replicas >= 1`

The `:latest` tag policy is commented out — see the comment in `policies/kubernetes.rego` for why.

---

## 8. Kubernetes Hardening

All application manifests implement the following security context pattern:

```yaml
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1001           # non-root UID
  containers:
    - name: my-service
      securityContext:
        readOnlyRootFilesystem: true
        allowPrivilegeEscalation: false
        runAsNonRoot: true
        runAsUser: 1001
        capabilities:
          drop: [ALL]         # strip all Linux capabilities
      volumeMounts:
        - name: tmp
          mountPath: /tmp     # writable path for the app
  volumes:
    - name: tmp
      emptyDir: {}            # ephemeral, per-pod, not shared
```

**Why `readOnlyRootFilesystem: true` with `emptyDir`?**  
An immutable root filesystem prevents an attacker who gains code execution from writing malware to disk or tampering with application binaries. Node.js apps need `/tmp` writable; mounting an `emptyDir` volume at `/tmp` gives a writable scratch space without opening the entire filesystem.

**Why `capabilities: drop: [ALL]`?**  
Linux capabilities (`NET_ADMIN`, `SYS_PTRACE`, etc.) are the mechanism by which processes gain elevated privileges. Dropping all capabilities removes the attack surface even if the process runs as non-root.

---

## 9. Secrets Management

### Architecture

```
Azure Key Vault (crud-kv)
    │
    │  External Secrets Operator (ESO) sync (every 1h)
    ▼
Kubernetes Secret: boutique-secrets
    │
    │  secretKeyRef in pod env
    ▼
Application pods
```

**Why not `kubectl create secret` directly?**  
Manual secrets are overwritten by ESO on its next sync cycle. Always add secrets to Azure Key Vault first, then add an entry to the `ExternalSecret` resource.

### Adding a new secret

```bash
# 1. Add to Azure Key Vault
az keyvault secret set --vault-name crud-kv \
  --name boutique-MY-SECRET \
  --value "mysecretvalue"

# 2. Patch the ExternalSecret to include it
kubectl edit externalsecret boutique-secrets -n boutique
# Add under .spec.data:
#   - secretKey: MY_SECRET
#     remoteRef:
#       key: boutique-MY-SECRET

# 3. Force immediate sync
kubectl annotate externalsecret boutique-secrets \
  force-sync=$(date +%s) --overwrite -n boutique

# 4. Verify
kubectl get secret boutique-secrets -n boutique -o jsonpath='{.data}' | jq 'keys'
```

### Harness Secrets

Connector credentials (Docker Hub token, GitHub PAT) are stored as Harness Secrets in Project Settings → Secrets. They reference identifiers in pipeline YAML (`tokenRef: github_pat`) rather than embedding values.

### Never commit generated vendor manifests with embedded credentials

The Harness GitOps agent (`k8s/argo/gitops-agent.yaml`) is generated by Harness and contains a real RSA private key as the agent token. **Do not commit the generated file to Git.** The copy in this repo has the key replaced with a `<REDACTED>` placeholder.

Workflow for anyone forking this repo:
1. Harness UI → Deployments → GitOps → Agents → `+New Agent` → Generate YAML
2. Apply it directly to the cluster: `kubectl apply -f gitops-agent.yaml -n argocd`
3. Do not `git add` it — `.gitignore` excludes `gitops-agent-live.yaml` for this reason

The same pattern applies to any Helm-generated output that contains `kind: Secret` with real values (delegate tokens, mTLS certs, API keys). Always inspect `helm template` output before committing it.

If a real key is accidentally committed: rotate it immediately in the issuing system (the old key is compromised regardless of whether you delete it from git history — it was readable to anyone with repo access from the moment it was pushed). Then optionally purge it from git history with `git filter-repo`.

### HashiCorp Vault (production pattern)

For teams at scale, replace ESO+AKV with Vault:
- Vault Agent Injector (mutating webhook) — annotate pods to receive secrets as files
- Kubernetes auth method — pod ServiceAccount JWT is exchanged for a Vault token
- Dynamic secrets — Vault generates a unique, time-limited DB credential per pod instead of a shared static password

---

## 10. GitOps with ArgoCD

### Three-tool split

| Layer | Tool | Model |
|---|---|---|
| Platform apps (ingress, ESO, monitoring) | ArgoCD | Pull — continuous reconciliation |
| Application services (boutique) | Harness | Push — gated pipeline execution |
| Harness GitOps | Harness UI | Unified visibility over ArgoCD apps |

### Connecting ArgoCD to Harness GitOps

1. Harness UI → Deployments → GitOps → Agents → `+New Agent`
2. Select "Existing ArgoCD" and your namespace (`argocd`)
3. Install the generated YAML into the cluster
4. The agent appears as `Healthy + Connected`

**What this enables:**
- See all ArgoCD application sync status inside Harness
- Trigger ArgoCD syncs as a step inside a Harness pipeline
- Unified RBAC — Harness groups control who can sync which ArgoCD app

### Argo Rollouts (progressive delivery without Harness)

For teams that want canary/blue-green managed entirely in Git (GitOps model):

```yaml
apiVersion: argoproj.io/v1alpha1
kind: Rollout
metadata:
  name: gateway
spec:
  strategy:
    canary:
      steps:
        - setWeight: 20
        - pause: {duration: 10m}
        - setWeight: 50
        - pause: {duration: 10m}
      canaryService: gateway-canary
      stableService: gateway-stable
      trafficRouting:
        nginx:
          stableIngress: gateway-ingress
```

ArgoCD syncs this from Git; Argo Rollouts controller manages the traffic split. No Harness pipeline needed for the canary logic — but you lose the Harness approval gate and audit trail.

---

## 11. Deployment Strategies

### Rolling (active — all services)

Kubernetes replaces pods incrementally. At any point, some pods run the old version and some run the new. Rollback restores the previous ReplicaSet.

```
v1 v1 v1 v1  →  v2 v1 v1 v1  →  v2 v2 v1 v1  →  v2 v2 v2 v2
```

**Harness step:** `K8sRollingDeploy` + `K8sRollingRollback`  
**Best for:** Most services; simple to operate; zero additional infra cost

### Canary (example — `.harness/pipeline-canary.yaml`)

Route a small percentage of traffic to the new version while the majority stays on stable. Validate metrics before promoting.

```
100% v1  →  80% v1 + 20% v2  →  [approve]  →  100% v2
```

**Harness steps:** `K8sCanaryDeploy` → `HarnessApproval` (or SRM verification) → `K8sRollingDeploy`  
**Rollback:** `K8sCanaryDelete` removes canary pods instantly  
**Best for:** High-traffic entry-point services (gateway, frontend)

### Blue-Green

Two identical Deployments. Traffic switch is instant (Service selector change).

```
[Service → blue pods]    deploy green → test green → switch Service → [Service → green pods]
```

**Harness steps:** `K8sBlueGreenDeploy` → `K8sBGSwapServices`  
**Best for:** Services with strict zero-downtime requirements; instant rollback needed  
**Cost:** 2x compute during the switch window

---

## 12. Observability

### OpenTelemetry (in services)

All backend services are instrumented with `@opentelemetry/auto-instrumentations-node`. Traces are exported to Jaeger via OTLP:

```yaml
env:
  - name: OTLP_ENDPOINT
    value: "http://jaeger:4318/v1/traces"
```

### Prometheus metrics (product-service)

The product-service exposes `/metrics` with annotations for scraping:

```yaml
annotations:
  prometheus.io/scrape: "true"
  prometheus.io/port: "3003"
  prometheus.io/path: "/metrics"
```

### Harness SRM (deployment verification)

Connect SRM to Prometheus/Datadog to add a `ContinuousVerification` step after deploy. SRM compares canary pod metrics vs primary pod metrics over a 10-minute window. If error rate or p99 latency degrades beyond threshold, Harness auto-rolls back — no human approval needed.

---

## 13. DORA Metrics

Harness tracks all four DORA metrics natively under Deployments → Overview.

| Metric | How measured | Target |
|---|---|---|
| Deployment Frequency | Pipeline executions per day/week | Daily or multiple times/day |
| Lead Time for Changes | Commit timestamp → CD stage completion | < 1 hour |
| Change Failure Rate | Rollback events / total deploys | < 5% |
| MTTR | Incident start → successful recovery deploy | < 1 hour |

**With automated rollback:** MTTR for deploy-caused incidents approaches zero — Harness detects the failure (failed readiness probe, health check) and triggers rollback without paging anyone.

---

## 14. Adapting for Other Kubernetes Providers

This project was built on AKS but the Harness connector model works identically on any Kubernetes distribution. The only thing that changes is **how the Delegate authenticates to the API server** and any provider-specific quirks.

### Connector files by provider

| Provider | Connector file | Auth method |
|---|---|---|
| AKS (Azure) | [k8s-aks.yaml](.harness/connectors/k8s-aks.yaml) | InheritFromDelegate + Azure Managed Identity |
| EKS (AWS) | [k8s-eks.yaml](.harness/connectors/k8s-eks.yaml) | InheritFromDelegate + IRSA |
| GKE (GCP) | [k8s-gke.yaml](.harness/connectors/k8s-gke.yaml) | InheritFromDelegate + Workload Identity |
| Vanilla / Rancher / kind | [k8s-generic.yaml](.harness/connectors/k8s-generic.yaml) | InheritFromDelegate or SA token |
| OpenShift | [k8s-generic.yaml](.harness/connectors/k8s-generic.yaml) | InheritFromDelegate (see SCC notes) |

### How auth works on each cloud

```
AKS    → Delegate SA + Azure AD Managed Identity → Azure APIs
EKS    → Delegate SA + IRSA (OIDC federation)    → AWS IAM
GKE    → Delegate SA + Workload Identity         → GCP Service Account
Other  → Delegate SA with cluster-admin binding  → K8s API server only
```

All three cloud-native patterns share the same principle: the **Kubernetes ServiceAccount is federated to a cloud IAM identity** via OIDC. No static key files. No credential rotation.

### Changing the provider — checklist

1. **Install Delegate** in the new cluster:
   ```bash
   helm install harness-delegate harness/harness-delegate \
     --namespace harness-delegate-ng --create-namespace \
     --set delegateName=<your-delegate-name> \
     --set accountId=<HARNESS_ACCOUNT_ID> \
     --set delegateToken=<HARNESS_DELEGATE_TOKEN>
   ```

2. **Update `delegateSelectors`** in your connector YAML to match the new Delegate name.

3. **Update `masterUrl`** only if using Pattern B (manual kubeconfig) — not needed for InheritFromDelegate.

4. **No changes needed** to: pipeline YAML, service YAML, infrastructure definition namespace, or application manifests. The deploy logic is provider-agnostic.

### OpenShift-specific notes

OpenShift's **Security Context Constraints (SCC)** are stricter than Kubernetes PodSecurityAdmission. Things to watch:

| Issue | Cause | Fix |
|---|---|---|
| `unable to validate against any SCC` | `runAsUser: 1001` outside namespace UID range | `oc adm policy add-scc-to-user anyuid -z <sa> -n boutique` |
| Ingress not working | OpenShift uses Routes, not Ingress | Install nginx-ingress or replace `k8s/ingress.yaml` with an OpenShift Route |
| Build pods failing | Kaniko needs `--context=dir://` on OpenShift | Set `privileged: true` on build SA or use Buildah instead of Kaniko |

The security context settings in all `k8s/*.yaml` manifests (`readOnlyRootFilesystem: true`, `capabilities: drop: [ALL]`) are **compatible with OpenShift restricted-v2 SCC** — no changes needed for application manifests.

### kind (local development)

kind clusters are the fastest way to practice without cloud costs:

```bash
# Create a kind cluster with a reachable API server
cat <<EOF | kind create cluster --config=-
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
networking:
  apiServerAddress: "0.0.0.0"
  apiServerPort: 6443
EOF

# Get the kubeconfig for Harness (Pattern B connector)
kubectl create serviceaccount harness -n kube-system
kubectl create clusterrolebinding harness-admin \
  --clusterrole=cluster-admin \
  --serviceaccount=kube-system:harness
kubectl create token harness -n kube-system --duration=8760h
```

Store the token as a Harness Secret and use the `k8s-generic.yaml` Pattern B connector with `masterUrl: https://localhost:6443`.

**Limitation:** kind runs inside Docker on your laptop. The Harness SaaS cannot reach `localhost:6443` — you need a tunnel (ngrok, Tailscale, or Cloudflare Tunnel) or run a local Harness installation.

### Rancher

Rancher wraps standard Kubernetes (RKE/RKE2/K3s). InheritFromDelegate works unchanged. Key points:

- Install the Delegate into the **downstream cluster** (not the Rancher management cluster)
- If using Rancher's built-in authentication, create a ServiceAccount in the downstream cluster with cluster-admin binding — do not use Rancher API tokens as the Harness SA token
- RKE2 nodes use containerd; Kaniko CI builds work without modification

---

## Branch Structure

| Branch | Purpose |
|---|---|
| `main` | Production — Harness CD + GHA CI (Scenario B) |
| `feat/gha` | Feature branch where Scenario B was developed |

## Contributing

This repo is a learning resource. PRs that add:
- Additional Harness pipeline examples (ECS, serverless, blue-green)
- Terraform module examples
- Ansible playbook examples
- Vault integration patterns
- Additional OPA policies

...are welcome. All PRs must pass the PR gate before merge.
