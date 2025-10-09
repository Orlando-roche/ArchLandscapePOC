# Architecture Landscape — POC

> Automated, always-fresh architecture from code, configs, and CI.

## TL;DR
- Generate an **Architecture Fact Model (AFM)** + **diagram** from the repo.
- Comment results on PRs/MRs and validate against governance rules.
- Optionally aggregate across repos in a central registry for org views.

---

## 1) End-state architecture

```mermaid
graph LR
  %% Central-led, PR-aware; safe quoted labels
  subgraph repos["Code Sources"]
    A["Repo A — Web (GitHub)"]
    B["Repo B — Android (GitLab)"]
    C["Repo C — API (GitHub)"]
  end

  subgraph central["Central Scanner Repo"]
    O["'archscan' Orchestrator"]
    R["Rule Packs (Semgrep / Regex)"]
  end

  subgraph signals["Signals Collected"]
    S1["Source code (.kt/.java/.js/.py)"]
    S2["Build & deps (Gradle, buildSrc/Dependencies.kt, Version Catalogs)"]
    S3["Configs (AndroidManifest, OpenAPI/AsyncAPI, YAML)"]
    S4["IaC (Kubernetes/Terraform)"]
    S5["Runtime (OpenTelemetry / Mesh)"]
  end

  subgraph facts["Fact Registry & Services"]
    F["AFM Registry (JSON store)"]
    M["Merger/Deduper (cross-repo)"]
    G["Governance Validator (policies)"]
    X["AI/Agents ('namer', 'summarizer', 'drift explainer')"]
  end

  subgraph out["Delivery & Feedback"]
    P["PR/MR Comment (Mermaid + AFM)"]
    D["Landscape Dashboard (org/domain views)"]
    K["Component Docs (cards from AFM)"]
  end

  subgraph dev["IDE & Local Dev (optional)"]
    I["IDE Command / Pre-commit (archscan preview)"]
  end

  A-->O; B-->O; C-->O
  S1-->O; S2-->O; S3-->O; S4-->O; S5-->O
  O-->R
  O-- "emit" -->F
  O-- "validate" -->G
  G-- "status" -->O
  F-->M
  M-->X
  M-- "global diagrams" -->D
  M-- "cards" -->K
  O-- "PR/MR diagram + AFM" -->P
  I-- "preview diagram" --> dev
  ```

---

  ## 2) Lightweight AFM (what we store)

```json
  {
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "Architecture Fact Model (AFM)",
  "type": "object",
  "required": [
    "components",
    "relations"
  ],
  "properties": {
    "components": {
      "type": "array",
      "items": {
        "type": "object"
      }
    },
    "relations": {
      "type": "array",
      "items": {
        "type": "object"
      }
    }
  }
}
```

**Principles**
- Every node/edge has **evidence** and a **confidence**.
- IDs are stable (kebab-case), names are human-friendly.
- Keep it small; add fields only when they drive decisions.

---

## 3) Where facts come from (signals)