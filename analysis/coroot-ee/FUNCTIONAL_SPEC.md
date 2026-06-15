# Coroot Enterprise Edition — Clean-room Functional Specification

**Specification target**: `coroot-ee` binary v1.22.0, `github.com/coroot/enterprise` v1.22.0, Go 1.25.11, linux/arm64 (CGO enabled, not stripped).

**Specification date**: 2026-06-13.

---

## 0. Clean-room framing

This document is a **clean-room functional specification**. It describes **what the system does** — its external behavior, contracts, data shapes, and workflows — at a level of abstraction independent of any specific implementation. It is intended to enable a re-implementation team to build a compatible system without reference to the original source code, algorithms, or libraries.

**Source materials consulted** (read-only):

- The compiled binary `coroot-ee` and its static artefacts in this directory (`symbols.txt`, `strings-n6.txt`, `paths.txt`, `urls.txt`, `main-main.disasm.txt`, `osv-*`, `deps.tsv`, `buildinfo.txt`).
- An open-source clone of the upstream Coroot Community Edition v1.22.0 (`coroot-src/`), used **only** to understand the public, externally observable behavior of the platform — i.e. the API surface, the data model shape, the persistence semantics, and the inspection cycle. No code, algorithm, internal type, or library choice from the clone is reproduced, recommended, or assumed in this specification. The clone is present in the workspace as a behavioral reference; a re-implementation does not need it.

**What this document does NOT contain**: code, algorithm pseudocode, library recommendations, internal type names, internal package names, or any other implementation detail that a re-implementation should be free to choose. Where the binary or the OSS clone shows a specific behavior that is **required for compatibility** (an external contract), it is documented as a contract; where a behavior is internal and could be re-implemented many ways, it is described only as "the system does X" without prescribing how.

**Out of scope**: this specification does not authorize, recommend, or describe how to bypass, crack, or invalidate the license-management subsystem. License enforcement is documented as a behavioral contract — i.e. "the system validates the license key against an external service and refuses to operate in some modes if validation fails" — without specifying how to circumvent it.

**What "compatibility" means here**: a re-implementation is "compatible" if it accepts the same inputs, produces the same externally visible outputs, and supports the same workflows as the target system. It is **not** required to share the same internal data layout, wire formats for stored data, or processing algorithms. The contract is at the user-visible and operator-visible surface.

---

## 1. System overview and purpose

### 1.1 What the system is

Coroot Enterprise Edition is an **observability / AIOps platform for containerized microservices**. It ingests telemetry (metrics, traces, logs, profiles) from instrumented applications, builds a live topology of the deployed system, continuously evaluates a library of health checks ("inspections") against that topology, opens and resolves incidents and alerts when checks fire, delivers notifications to operator-chosen channels, and (in the Enterprise tier) uses an external large-language-model provider to produce root-cause analysis and statistical-anomaly explanations.

The system is designed to be **zero-touch for application developers**: the typical deployment uses the open-source Coroot Node Agent sidecar, which auto-discovers services, instruments them via eBPF / OpenTelemetry SDKs, and forwards telemetry to a Coroot server using industry-standard protocols. Operators deploy the server; the agents are deployed alongside applications.

### 1.2 Edition model

The system ships as a single binary that behaves as either:

- **Community Edition** — the binary runs without a license key, exposes the full OSS feature set, and is the same code path as Enterprise minus the Enterprise-only features. There is no separate Community binary; the same binary detects the absence of a license key and switches behavior.
- **Enterprise Edition** — the binary runs with a license key, validates it against a remote license service, and unlocks the Enterprise-only features: AI-assisted root-cause analysis, AI-assisted anomaly explanation, AI provider configuration, SAML and OIDC single-sign-on, custom roles, and any other features whose user-facing affordances are gated on `CheckLicense()` returning "valid".

The binary is not stripped of any feature; the gating is at runtime based on license state.

### 1.3 Deployment model

A Coroot server is a **single Go binary process** with the following optional runtime dependencies:

- **Configuration database** — SQLite (default, file-based) or PostgreSQL (optional). Stores all durable metadata: users, projects, integrations, alerting rules, dashboards, applications, incidents, alerts, notifications, settings, license state, SSO config, AI config.
- **Time-series cache** — on-disk Prometheus-style TSDB stored under `<data-dir>/cache`. Stores metrics, trace summaries, log indexes, and profile metadata. Subject to a configurable TTL with periodic garbage collection.
- **ClickHouse** (optional) — used for long-term storage of logs, traces, and profiles when the cache TTL is shorter than the operator's data-retention requirement. ClickHouse is also a valid query backend for metrics in place of an external Prometheus. Multiple ClickHouse instances can be configured per project.
- **Prometheus** (optional) — used as a query backend for metrics. The system can be configured to use Prometheus as the source of truth for metrics, or ClickHouse, or a combination. A separate Prometheus endpoint can be configured for "remote write" ingestion from external sources.
- **Coroot Cloud** (optional) — a SaaS service operated by the Coroot vendor, used for: (a) license validation, (b) version-update checks, (c) opt-in anonymous usage statistics. The system is fully functional offline; Coroot Cloud is required only for the license check, the update check (if enabled), and the usage-statistics path (if enabled).

A single instance of the binary serves one or more **projects** (logical groupings of telemetry; typically one per cluster or one per business unit). Multiple instances of the binary can be run in active/standby against the same configuration database; the active instance is elected via a database lock (`GetPrimaryLock`).

### 1.4 What the system does NOT do

- It does not act as a general-purpose time-series database; it is an analytics-and-alerting layer on top of a TSDB.
- It does not own long-term storage of logs, traces, or metrics; it reads them and writes them to the configured storage backend, but the data is not its primary product.
- It does not perform any out-of-band network actions beyond the configured integrations (no telemetry to third parties without explicit configuration; no automatic outbound calls to Coroot Cloud unless the operator has enabled usage statistics or the operator has configured a license key).

---

## 2. Architecture

### 2.1 Process model

The system is a **single process** that runs several subsystems concurrently. The runtime topology is:

```
                 ┌──────────────────────────────────────────────────┐
                 │                  main process                      │
                 │                                                   │
   ── HTTP ───►  │   HTTP server  ──►  router  ──►  auth  ──►  API  │  ◄── gRPC/OTLP, MCP
                 │                       (gorilla/mux, prefix-aware) │
                 │                                                   │
   telemetry ──► │   collector    ──►  time-series cache  ──►  CH  │  (ingest)
                 │                                                   │
                 │   constructor  ◄──  cache  ─►  world model       │  (analytical state)
                 │       │                                           │
                 │       ▼                                           │
                 │   auditor  ──►  checks  ──►  alerts / incidents   │  (inspection cycle)
                 │                          │                        │
                 │                          ▼                        │
                 │   notifications  ──►  external channels          │  (delivery)
                 │                                                   │
                 │   watchers  ──►  incidents / deployments          │  (lifecycle)
                 │                                                   │
                 │   rca  ──►  external AI provider  ──►  report     │  (Enterprise)
                 │                                                   │
                 │   license manager  ──►  external license server   │  (Enterprise)
                 │                                                   │
                 │   stats  ──►  external usage-statistics endpoint  │  (opt-in)
                 │                                                   │
                 │   cloud-pricing  ──►  rate-card repository         │  (cost data)
                 └──────────────────────────────────────────────────┘
                                       │
                                       ▼
                              Configuration DB (SQLite / Postgres)
```

### 2.2 Subsystem responsibilities

Each subsystem is a logical boundary. A re-implementation may merge or split these as long as the externally observable behavior is preserved.

| Subsystem | Responsibility |
|---|---|
| HTTP server | Exposes the REST API, the static SPA, the MCP streamable HTTP endpoint, the OAuth endpoints, the Prom-compatible endpoints, the collector HTTP endpoints, and the pprof endpoints. |
| gRPC server | Exposes the OpenTelemetry Protocol (OTLP) traces and logs services. Optional (can be disabled). |
| Collector | Handles ingestion of metrics, traces, logs, profiles, and agent config exchange. Validates the API key, looks up the project, writes to the cache (and ClickHouse for traces/logs/profiles). |
| Time-series cache | Stores the raw telemetry with a chunked on-disk format; serves PromQL range queries, label queries, metric metadata queries; runs a periodic garbage collector. |
| ClickHouse integration | Optional, for long-term storage of logs, traces, profiles, and (optionally) metrics. |
| Constructor | Builds the "world model" — the live topology of the system — by reading the cache for the relevant time window and assembling Applications, Instances, Nodes, Containers, Pods, and their relationships. |
| Auditor | Runs the inspection cycle: for each project, run the catalog of inspectors against the world, produce Checks. |
| Watchers | Orchestrate the lifecycle: incidents, alerts (creation, deduplication, resolution, suppression, re-open), and deployments (detection from k8s, Argo CD, Flux). |
| Notifications | Dispatch notifications about incidents, alerts, and deployments to configured external channels. |
| Stats | Optional anonymous usage-statistics upload to Coroot Cloud. |
| Cloud pricing | Downloads the cloud provider rate-card data (AWS, GCP, Azure) for cost calculations. |
| License manager (Enterprise) | Validates the license key against the Coroot Cloud license service on a periodic basis; exposes `CheckLicense()` to gate Enterprise features. |
| RCA (Enterprise) | Assembles signals about an incident (deployments, configuration changes, k8s events, log patterns, profiles, traces), calls an external AI provider (Anthropic, OpenAI, or OpenAI-compatible), and returns a structured root-cause report. |
| Anomaly detection (Enterprise) | Tracks statistical baselines of metrics, identifies deviations, and (when configured) calls an external AI provider for a human-readable explanation. |
| Authentication | Validates session cookies, API keys, and OAuth/OIDC/SAML tokens; maps users to roles; enforces RBAC permissions. |
| MCP server | Exposes the platform's data and operations to Model-Context-Protocol clients (AI agents) via a stateful streamable HTTP transport. |

### 2.3 Data flow

**Telemetry path** (in):

1. An agent (or external system) sends metrics, traces, logs, or profiles to a collector endpoint. Auth is by API key (`X-API-Key`).
2. The collector validates the key, looks up the project, and writes to the time-series cache. For traces, logs, and profiles, it may also write to ClickHouse.
3. The cache notifies the watchers (via an internal update event) that there is fresh data for the project.

**Inspection path** (analytics):

1. The watchers receive a "data is fresh" signal for a project.
2. The constructor builds a fresh world model for the project over the inspection time window (default 15 seconds, configurable).
3. The auditor runs its inspectors against the world, producing checks (each with a status: OK / WARNING / CRITICAL / UNKNOWN).
4. The checks are aggregated: a check that newly fires creates or updates an alert; alerts for the same application in the same time window are grouped into an incident.
5. If the alert matches a notification rule, a notification record is created; the notifications subsystem delivers it to the configured channel(s).
6. The world model, checks, and incident data are persisted (in part) to the configuration database for retrieval via the API.

**User-facing path** (out):

1. A user loads the SPA in a browser (or an external system makes an API call).
2. The server returns the rendered `index.html` (which boots the SPA), and the SPA then makes API calls to populate the views.
3. API calls are authenticated by session cookie; RBAC checks are applied per request; the appropriate data is returned.

**AI path** (Enterprise, optional):

1. A user opens an incident detail page, or an external MCP client calls an investigation tool.
2. The server's RCA subsystem gathers signals (deployments, config changes, k8s events, log patterns, profiles, traces, related metrics) and constructs a prompt.
3. The prompt is sent to the configured AI provider; the response is parsed into a structured root-cause report (problem statement, correlation chart, suggested immediate fixes, related logs, related metrics).
4. The report is cached on the incident and returned to the user / MCP client.

### 2.4 Concurrency model

- The HTTP server is multithreaded (one request-handling task per request).
- The gRPC server is multithreaded.
- The cache uses an in-memory index over the on-disk chunk files; reads are concurrent; writes are serialized per project.
- The inspection cycle is triggered by the cache notifying the watchers; a deduplicating worker coalesces multiple "data is fresh" signals for the same project.
- A database lock (acquired via the configuration database) elects the primary instance in a multi-instance deployment; only the primary runs the watchers.

---

## 3. External interfaces

The system exposes its functionality through three externally visible surfaces: an HTTP API, a gRPC/OTLP service, and an MCP server. The HTTP API is the primary user-facing surface.

### 3.1 HTTP API

The HTTP API is mounted on the configured listen address. When the `url_base_path` is set to a value other than `/`, all routes are mounted under that prefix. The collector ingest endpoints (`/v1/*`) are explicitly re-registered in the sub-router so that they keep their original paths.

#### 3.1.1 Auth model

The HTTP API uses **three authentication classes**, applied per route:

1. **Session cookie** — a signed cookie issued by the `Login` endpoint. Used for all UI-facing routes. The cookie is opaque to the user, httpOnly, scoped to `/`, with a 7-day lifetime. It carries a JSON payload (containing the user identifier) signed with HMAC-SHA256 using a server-side secret. The server-side secret is stored in the configuration database under a fixed setting name and is auto-generated on first startup. Logout clears the cookie.

2. **API key** — an `X-API-Key` HTTP header. Used for collector ingest and for the Prom-compatible query endpoints. Each API key is associated with one project (excluding multi-cluster projects). The key value is a non-empty string. Keys are managed via the API keys endpoint; deletion removes the key from the project's settings.

3. **OAuth bearer (MCP)** — a JWT issued by the system's own OAuth 2.0 authorization server. Used for the MCP endpoint. The token is HS256-signed with the same server-side secret as the session cookie, but uses a different audience claim. The OAuth server supports dynamic client registration (public clients only, no client secret), authorization code with PKCE (S256), refresh token, and revocation.

In addition:

- **OIDC / SAML** (Enterprise): the system acts as a service provider. OIDC uses the standard authorization-code flow; SAML uses HTTP-POST binding. Successful authentication either provisions a new local user (configurable) or maps to an existing user. After successful SSO, the user is issued a normal session cookie.

- **Anonymous access**: if the operator has set `auth_anonymous_role` to a valid role name at startup, every request is treated as authenticated as that role. This is the only mechanism that makes a deployment reachable without a login.

#### 3.1.2 RBAC

The system supports two role models:

- **Static role set** (default): three built-in roles — Admin, Editor, Viewer. A user has one or more of these roles. Permissions are scope-keyed: some permissions are global (settings, users, roles), most are project-scoped. Within a project, permissions are further scoped by resource kind (applications, nodes, dashboards, alerting rules, alerts, traces, logs, costs, risks, etc.).
- **Custom roles** (Enterprise): roles can be defined and persisted in the configuration database, with arbitrary permission sets. The custom-role model uses the same permission model as the static roles.

A user's effective permissions are the union of all permissions granted by all of their roles. Permission scopes use a glob match for object-level filters (e.g. an application filter is `project_id + category + namespace + kind + name`, each glob-matchable).

#### 3.1.3 Route table

The following table lists every HTTP route the system exposes. Routes are grouped by authentication requirement. Path placeholders use `{name}` for path parameters and `{rest:.+}` for catch-all.

##### Public (no auth)

| Method | Path | Purpose |
|---|---|---|
| GET | `/health` | Liveness probe. Returns an empty 200 response. |
| POST | `/stats` | Ingest an opt-in usage-statistics record. |
| GET | `/stats` | Return the collected usage statistics. |
| POST | `/api/login` | Authenticate a user with email + password and issue a session cookie. Also handles the first-boot `set_admin_password` action. |
| POST | `/api/logout` | Clear the session cookie. |
| GET | `/.well-known/oauth-protected-resource` | RFC 8707 resource-server metadata for MCP. |
| GET | `/.well-known/oauth-authorization-server` | RFC 8414 authorization-server metadata for MCP. |
| POST | `/oauth/register` | Dynamic client registration. Public client only. |
| GET | `/oauth/authorize` | Show the consent UI. |
| POST | `/oauth/authorize` | Process the consent decision; on approval, issue a short-lived authorization code and redirect. |
| POST | `/oauth/token` | Exchange an authorization code (with PKCE verifier) or a refresh token for an access token. |
| POST | `/oauth/revoke` | Accept a revocation request. |
| GET | `/api/sso-status/{status}` | Status page displayed at the end of an SSO flow. |
| GET | `/api/sso-login/{provider}` | Begin an SSO flow with the given provider. |
| GET | `/auth/mcp-consent` | Consent UI for the MCP OAuth flow (rendered by the SPA). |
| GET | `/api/saml/acs` | SAML assertion consumer service endpoint. |
| GET | `/api/oidc/callback` | OIDC callback endpoint. |
| GET | `/static/{rest:.+}` | Serve a static UI asset. |
| any | `/` (and any path under `url_base_path` that does not match another route) | Serve the SPA `index.html`. |

##### Session-authenticated (most of the `/api/*` and `/api/project/*` surface)

| Method | Path | Purpose |
|---|---|---|
| GET, POST | `/api/user` | Get / update the current user. POST changes the user's own password. |
| GET, POST | `/api/users` | List users + roles (Editor or above); create / update / delete a user. |
| GET | `/api/roles` | List roles (static + custom + illustrative samples). |
| GET, POST | `/api/sso` | Get / save SSO configuration (Enterprise). |
| GET, POST | `/api/ai` | Get / save the AI provider configuration (Enterprise). |
| GET, POST | `/api/cloud` | Get / save Coroot Cloud integration settings. |
| GET, POST, DELETE | `/api/project/` (and `/api/project/{project}`) | List / create / update / delete projects. |
| GET | `/api/project/{project}/status` | Project-level status (overall health). |
| GET, POST | `/api/project/{project}/api_keys` | List or manage API keys. |
| GET | `/api/project/{project}/overview/{view}` | Render an overview page. `view` ∈ `services` (default), `traces`, `logs`, `costs`, `risks`. |
| GET | `/api/project/{project}/incidents` | List recent incidents. |
| GET | `/api/project/{project}/incident/{incident}` | Detail for a single incident. |
| GET | `/api/project/{project}/alerts` | List alerts (with filters, search, sort, pagination). |
| POST | `/api/project/{project}/alerts/resolve` | Manually resolve alerts. |
| POST | `/api/project/{project}/alerts/suppress` | Suppress alerts. |
| POST | `/api/project/{project}/alerts/reopen` | Re-open resolved or suppressed alerts. |
| GET | `/api/project/{project}/alerts/{alert}` | Detail for a single alert. |
| GET, POST | `/api/project/{project}/alerting-rules` | List or create custom alerting rules. |
| GET | `/api/project/{project}/alerting-rules/export` | Export rules as YAML. |
| GET, PUT, DELETE | `/api/project/{project}/alerting-rules/{rule}` | One alerting rule: get, update, delete. |
| GET, POST | `/api/project/{project}/dashboards` | List / create dashboards; POST also saves panel configuration. |
| GET, POST | `/api/project/{project}/dashboards/{dashboard}` | One dashboard: get / update. |
| GET | `/api/project/{project}/panel/data` | Evaluate a dashboard panel. |
| GET | `/api/project/{project}/inspections` | List inspection configurations for the project. |
| GET, POST | `/api/project/{project}/application_categories` | List / manage application categories. |
| GET, POST | `/api/project/{project}/custom_applications` | List / manage custom application definitions. |
| GET, POST, DELETE | `/api/project/{project}/custom_cloud_pricing` | Read / save / clear custom cloud pricing. |
| GET, PUT | `/api/project/{project}/integrations` | List integrations + base URL. PUT updates the base URL. |
| GET, PUT, DELETE, POST | `/api/project/{project}/integrations/{type}` | Per-integration form for `type` ∈ `prometheus`, `clickhouse`, `aws`, `slack`, `teams`, `pagerduty`, `opsgenie`, `webhook`. GET shows the form; POST tests the connection; PUT saves; DELETE clears. |
| GET | `/api/project/{project}/app/{app}` | Application detail (audit report, DB change events for DB apps, etc.). `{app}` is a 4-part identifier: `cluster_id:namespace:Kind:name`, URL-encoded. |
| GET | `/api/project/{project}/app/{app}/rca` | Request AI-driven root-cause analysis. If `?incident=...` is set, results are persisted on the incident. |
| GET, POST | `/api/project/{project}/app/{app}/inspection/{type}/config` | Get / save the inspection form (e.g. SLO availability, SLO latency). |
| GET, POST | `/api/project/{project}/app/{app}/instrumentation/{type}` | Get / save instrumentation (e.g. OpenTelemetry SDK config). Credentials are masked on read if the caller is not an Editor. |
| GET, POST | `/api/project/{project}/app/{app}/profiling` | Profiling view (ClickHouse-backed). |
| GET, POST | `/api/project/{project}/app/{app}/tracing` | Tracing view (ClickHouse-backed). |
| GET, POST | `/api/project/{project}/app/{app}/logs` | Logs view (ClickHouse-backed). |
| POST | `/api/project/{project}/app/{app}/risks` | Dismiss a risk or re-mark a risk as active. |
| GET | `/api/project/{project}/node/{node}` | Single-node audit report. `{node}` is `clusterId:nodeName`; the `clusterId` may be empty. |
| GET | `/api/project/{project}/rca_dump` | Dump the world model at a time window, for offline RCA. |
| GET | `/api/project/{project}/anomalies` | List anomalies (Enterprise). |
| GET | `/api/project/{project}/anomalies/{anomaly}` | Anomaly detail (Enterprise). |
| GET | `/api/project/{project}/ai/analysis` | Read AI analysis state (Enterprise). |
| GET, POST | `/api/project/{project}/ai/promql` | Generate a chart suggestion for a PromQL query (Enterprise). |

##### Path-prefix (proxied Prom-compatible)

| Method | Path | Purpose |
|---|---|---|
| any | `/api/project/{project}/prom/api/v1/{rest:.+}` | In-cluster Prometheus proxy. Delegates to the project's Prom client. `X-Datasource` header selects a member project for multi-cluster projects. |

##### API-key authenticated (collector ingest + Prom query)

| Method | Path | Purpose |
|---|---|---|
| POST | `/v1/metrics` | Prometheus remote-write receiver. |
| POST | `/v1/traces` | OTLP/HTTP trace receiver. |
| POST | `/v1/logs` | OTLP/HTTP log receiver. |
| POST | `/v1/profiles` | Profile payload receiver (e.g. eBPF). |
| GET, POST | `/v1/config` | Agent / collector configuration exchange. |
| GET | `/api/v1/query_range` | Prometheus-compatible range query. |
| GET, POST | `/api/v1/series` | Prometheus series endpoint. |
| GET | `/api/v1/metadata` | Prometheus metric metadata. |
| GET | `/api/v1/label/{labelName}/values` | Prometheus label values. |
| GET | `/api/clickhouse-config` | Return the project's ClickHouse configuration (for node-agent discovery). |
| CONNECT | `/api/clickhouse-connect` | Raw TCP proxy from the agent into the project's ClickHouse (used after hijacking the HTTP connection). |

##### OAuth bearer (MCP)

| Method | Path | Purpose |
|---|---|---|
| any | `/mcp` | MCP streamable HTTP transport (stateful). Returns 401 + `WWW-Authenticate` if no valid bearer is present. |

##### pprof

| Method | Path | Purpose |
|---|---|---|
| any | `/debug/pprof/{rest:.*}` | Standard `net/http/pprof` handlers. |

### 3.2 gRPC / OTLP

A separate gRPC server is started on the configured listen address (default `:4317`). It can be disabled. The server registers two OTLP services:

- **OTLP traces** — accepts `ExportTraceServiceRequest`.
- **OTLP logs** — accepts `ExportLogsServiceRequest`.

Auth is by the `X-API-Key` gRPC metadata, which is resolved against the same project list as the HTTP API keys. Multicluster projects are skipped. Unknown or missing keys are rejected.

The gRPC server is built with no custom interceptors. The receive message size limit is set to a very large value (the maximum integer); operators are expected to enforce a reasonable limit at the network or proxy layer.

When TLS is configured, the gRPC server serves over HTTPS using the same certificate / key as the HTTPS HTTP listener.

### 3.3 MCP (Model Context Protocol)

The system runs a stateful MCP server at `/mcp`. The transport is streamable HTTP. Each tool call is RBAC-gated inside the handler. The server is instructed (via its `instructions` field) to:

1. Start with `list_projects` + `select_project` to pick the project context.
2. Pick tools by intent: alerts/incidents/applications first, then traces at three drill-down levels (summary, errors, outliers), logs, raw metrics, incident details.
3. Treat `resolve_alerts` as the only mutating tool for alerts.

The system has a notion of "active project" per MCP session, tracked in an in-memory map keyed by the MCP session ID. Project selection persists for the duration of the session.

The following MCP tools are registered. Each tool has annotations: `readOnlyHint`, `destructiveHint`, `idempotentHint`, `openWorldHint`. The user-visible descriptions match those returned in the OSS source.

| Tool | Read-only? | Purpose |
|---|---|---|
| `list_projects` | yes | List projects the caller can access; returns a `name → id` map. |
| `select_project` | no | Pin the active project for the session. |
| `list_applications` | yes | List applications in the active project with id, namespace, category, detected types, overall status, failing inspections. |
| `list_alerts` | yes | List alerts (filter by state, application, limit). |
| `list_incidents` | yes | List SLO incident summaries. |
| `resolve_alerts` | no | Manually resolve alerts (triggers downstream notifications). |
| `get_incident_details` | yes | Full incident: summary, RCA, propagation map. |
| `get_application_status` | yes | App health: overall status, per-inspection status, upstream dependencies, downstream clients. |
| `list_nodes` | yes | List hosts / VMs with name, cluster, status, OS, instance type, CPU/mem %, network throughput, GPUs. |
| `get_node_details` | yes | Per-node audit report + cpu/memory/network sparklines. |
| `traces_summary` | yes | Per-endpoint trace summary: rps, error rate, p50/p95/p99. |
| `traces_errors` | yes | Top error reasons grouped by endpoint, with sample trace id and sample error. |
| `traces_outliers` | yes | Latency flamegraph: slow-tail vs rest. |
| `get_trace` | yes | Full span tree for a single trace id. |
| `list_metric_names` | yes | Discover metric names by RE2 match. |
| `query_metrics` | yes | PromQL range query, with sparkline summaries. |
| `query_logs` | yes | ClickHouse-backed log query. |
| `list_anomalies` (Enterprise) | yes | List statistical anomalies with optional AI-explained ones. |
| `investigate_anomaly` (Enterprise) | no | AI-investigate an anomaly: takes an anomaly key, returns a structured explanation. |

Time arguments to the time-aware tools accept epoch milliseconds or relative strings like `now-1h`. Default windows are short (~1 hour) and must be widened explicitly for historical analysis.

The MCP server is tool-only: no resources are exposed.

---

## 4. Data model

The data model is organized into the following groups. Entities are described in terms of their **purpose** and the **fields** a re-implementation would need to support. Field names are illustrative; a re-implementation may use any naming convention.

### 4.1 Topology

The topology entities represent the **structure of the deployed system** as observed from telemetry and from optional integration with cluster APIs (k8s, Argo CD, Flux).

- **Project** — the top-level grouping. A project is a logical unit (typically one cluster or one business unit) for which the system stores telemetry, runs inspections, and fires alerts. Identifier: opaque string (UUID-shaped in the current implementation). Has settings: name, API keys, integrations, custom applications, application categories, custom cloud pricing, alerting rules, member projects (for multi-cluster projects), readonly flag.
- **Application** — a logical service. Identified by a 4-part id: `cluster_id:namespace:Kind:name`. Has a category (one of a fixed set, e.g. `Generic`, `Postgres`, `Redis`, `Kafka`, etc.), custom flag, annotations, instances, upstream and downstream connections, traffic stats, SLIs, events, deployments, incidents, log messages, status, reports, settings, kubernetes services, DNS requests, periodic-systemd-job flag.
- **Service** — a Kubernetes Service (or equivalent) fronting one or more pods. A service is reachable from the application's perspective; each service has a name, namespace, cluster, ports, and selection labels.
- **Instance** — a single replica of an application (typically one container / one pod). Has name, namespace, node, IP, ports, status, container, runtime info (e.g. JVM, Node.js, .NET, Python, Go), custom-application flag, observed/updated timestamps.
- **Node** — a host or VM. Has name, cluster, OS, instance type, CPU/memory/network statistics, GPU info, labels, status.
- **Container** — a container running inside a pod. Has name, image, limits/requests, status, restart count, OOM events.
- **Pod** — a k8s pod (or equivalent). Has name, namespace, cluster, node, containers, status, labels, creation timestamp.
- **Volume** — a persistent volume or emptyDir. Has name, kind, mount path, capacity, used, IO load, status.
- **Connection (service-to-service)** — an observed network connection from one service/application to another, with RTT statistics, error rate, latency distribution, and connectivity status.
- **Dependency map** — a graph view of applications and their connections, used by the overview page.

### 4.2 Behavior

- **Check** — a single finding produced by the inspector cycle. Has id (a fixed identifier from a known set), category (the report it belongs to: e.g. `CPU`, `Memory`, `Network`, `Instances`, `Deployments`, `SLO`, `Logs`, `Redis`, `Postgres`, `Mongodb`, `Mysql`, `Memcached`, `Jvm`, `DotNet`, `Python`, `Nodejs`, `Dns`, `Storage`, `Costs`, `Risks`, etc.), title, message (templated from the items it pertains to), status (`OK`, `WARNING`, `CRITICAL`, `UNKNOWN`), the items it pertains to, optional value, optional unit, optional threshold. The system defines a fixed catalog of checks (see §4.10).
- **Risk** — a long-lived issue that does not necessarily correspond to a current check. Has a key, category, type, message, dismissal state (active / dismissed), dismissal reason, first-seen, last-seen.
- **SLI (Service Level Indicator)** — either availability (% of successful requests) or latency (% of requests served faster than a configured threshold). Computed from the application's request data over a window.
- **SLO (Service Level Objective)** — the operator-set objective for one SLI. A pair of (objective percent, threshold for latency). Fires checks when the SLI is below the objective.
- **Application deployment** — a recorded deployment event for an application. Has an id, version, kind (k8s rollout, Argo CD sync, Flux release, manual), status, summary, deployment details (replicas old/new, container images), notifications config.
- **Application event** — a notable event in the application's lifecycle (e.g. OOM, restart, scale, error spike). Has type, message, timestamp, severity.
- **Application settings** — per-application overrides: tracing configuration, logging configuration, profiling configuration, instrumentation, custom log-pattern, custom SLI, custom availability SLO, custom latency SLO.
- **Application category** — a named bucket (e.g. `Databases`, `Queues`, `Caches`) with custom patterns (label selector or name match) that determine which applications fall into the category.
- **Custom application** — an application definition not auto-discovered, with instance patterns that identify it from telemetry.

### 4.3 Incidents and alerts

- **Incident** — a problem detected within a time window. Has a key (typically application + window), title, status (`OPEN`, `ACKNOWLEDGED`, `RESOLVED`), severity, opened/closed timestamps, list of involved alerts/checks, list of involved applications, RCA result, propagation map. State transitions: `OPEN` → `ACKNOWLEDGED` (operator), `OPEN` → `RESOLVED` (auto when conditions clear or manually), `RESOLVED` → `OPEN` (re-open).
- **Alert** — a single fired check. Has id, fingerprint (for deduplication), rule id, project id, application id, application category, severity, summary, details (list of `name → value` pairs), opened at, resolved at, manually-resolved at, updated at, suppressed flag, resolved-by, report (the report it belongs to), pattern words.
- **Alerting rule** — a rule that produces alerts. Has id, project id, name, source (one of: `check`, `promql`, `log_patterns`, `kubernetes_events`), selector (which applications to evaluate), severity, `for` duration (how long the condition must hold), `keep_firing_for` duration (how long after resolution to keep firing), templates (summary / description), notification category, enabled flag, readonly flag. Built-in rules exist by default; custom rules can be created per project; rules can be loaded from configuration files (which marks them as readonly).
- **Alert notification** — a delivery record for an alert. Has id, alert id, project id, application id, status (`FIRING` / `OK`), timestamp, destinations, sent flag, send attempts, last error, details.
- **Incident notification** — a delivery record for an incident. Has id, incident key, project id, application id, status (`OPEN` / `OK`), timestamp, destinations, sent flag, details (reports, RCA summary, RCA remediations).
- **Suppression** — a per-alert flag that prevents the alert from being re-sent. Cleared on re-open or on suppression reset.

### 4.4 Observability data

These are the kinds of telemetry the system ingests and queries against. They are stored in the time-series cache and (optionally) ClickHouse.

- **Metric series** — a time series with labels and (timestamp, value) pairs.
- **Trace** — a directed tree of spans, each with attributes, events, and a status.
- **Span** — a single operation in a trace, with name, service, kind, attributes, events, status, start/end times.
- **Log entry** — a single log line, with severity, timestamp, service, message, attributes.
- **Profile** — a sampled profile (CPU, allocation, inuse, query, Java diff, etc.), with a flamegraph representation.
- **Chart** — a series or grouped series for a metric, with labels, aggregation, and time range.
- **Widget** — a dashboard widget: a chart, a table, a heatmap, or a flame graph.
- **Table** — a tabular view (e.g. top-N applications by request rate, top-N error messages). A table has columns, rows, and a sort order.
- **Heatmap** — a 2D histogram view (e.g. latency by hour-of-day, request rate by status code).
- **Audit report** — the per-application or per-node report produced by the auditor for a time window. Has a name, status, and a list of checks.

### 4.5 Integrations

- **Integration** — a configured external system. Each integration has a type (`prometheus`, `clickhouse`, `aws`, `slack`, `teams`, `pagerduty`, `opsgenie`, `webhook`), a `configured` flag, and per-type configuration.
- **Integration: Slack** — token, default channel, separate flags for `incidents`, `deployments`, `alerts`.
- **Integration: MS Teams** — webhook URL, separate flags for `incidents`, `deployments`, `alerts`.
- **Integration: PagerDuty** — integration key, flags for `incidents`, `alerts`.
- **Integration: Opsgenie** — API key, EU-instance flag, flags for `incidents`, `alerts`.
- **Integration: Webhook** — URL, TLS-skip-verify, optional basic auth, custom headers, custom fields, flags for `incidents`, `deployments`, `alerts`, and three optional text templates (incident template, deployment template, alert template). Templates use a templating syntax (the form used by the Go `text/template` package).
- **Integration: Prometheus** — URL, refresh interval, TLS-skip-verify, optional basic auth, extra selector, custom headers, remote-write URL, "use ClickHouse instead of Prometheus" flag, global flag.
- **Integration: ClickHouse** — protocol (`native` or `coroot`), address, basic auth, database, initial database, TLS enable, TLS-skip-verify, global flag.
- **Integration: AWS** — region, access key id, secret access key, optional RDS tag filters, optional ElastiCache tag filters. (Used to populate cost data and to discover RDS/ElastiCache instances.)
- **Custom application definition** — see §4.2.
- **Application category** — see §4.2.
- **Custom cloud pricing** — per-resource-type pricing overrides: per CPU core per hour, per memory GB per hour, per GB transferred, etc.

### 4.6 Identity and access

- **User** — a principal. Has id, email (unique), name, password hash (bcrypt), roles, created/updated timestamps.
- **Role** — a named set of permissions. Has id, name, description, and a list of permission entries. Built-in roles: `Admin` (all permissions), `Editor` (all read permissions + a defined set of edit permissions per project), `Viewer` (read-only). Custom roles can be created in the Enterprise tier.
- **Permission** — a triple: scope, verb, object. `scope` is one of a fixed set (`settings`, `users`, `roles`, `project.*`, etc.); `verb` is `view` or `edit` (or `*` for all); `object` is a glob match against a key set (e.g. `{project_id, application_category, application_namespace, application_kind, application_name}` for application-scoped permissions, or `{project_id, node_name}` for node-scoped).
- **API key** — a per-project credential. Has key (the secret), description, created/updated timestamps. Empty `key` is treated as not set.
- **SSO config (Enterprise)** — OIDC config (issuer URL, client ID, client secret, claim mapping) and/or SAML config (metadata XML, entity ID, ACS URL, attribute mapping). Only one OIDC and one SAML can be configured per deployment.
- **AI config (Enterprise)** — provider choice (`Anthropic`, `OpenAI`, `OpenAI-compatible`), per-provider fields (API key, base URL for compatible, model name, max tokens, etc.), and a global enable flag.
- **License** — opaque key, plus cached validation state (status, expiry, tier, allowed-features, used-quota, grace-period). Stored in the configuration database.

### 4.7 Settings

- **Settings entries** — a key-value store in the configuration database. Known keys: `auth_secret` (auto-generated, holds the HMAC secret for session cookies and MCP JWTs), `deployment_uuid` (per data store), and license-related entries.
- **Per-project settings** — see §4.1.

### 4.8 Cloud pricing

- **Rate card** — a JSON file published by Coroot (downloaded from a static URL) containing cloud-provider unit prices (per CPU core per hour, per memory GB per hour, per GB transferred, etc.) by region and instance type. Downloaded on a periodic basis; cached in `<data-dir>/cloud-pricing`.
- **Cost data** — per-application or per-node cost, derived from the rate card and the resource consumption. Supports per-resource custom overrides.

### 4.9 Cloud integration

- **Coroot Cloud** — optional connection to a vendor SaaS for license validation, version update checks, and opt-in anonymous usage statistics. The system can save a per-deployment `api_key` and a boolean `incidents_auto_investigation` setting.

### 4.10 Inspection catalog (the fixed list of check ids)

The system has a fixed catalog of inspectors. Each inspector produces one type of check. The full set of check ids is:

- **SLO**: `slo_availability`, `slo_latency`
- **CPU**: `cpu_node`, `cpu_container`
- **Memory**: `memory_oom`, `memory_leak_percent`, `memory_pressure`
- **Storage**: `storage_space`, `storage_io_load`
- **Network**: `network_rtt`, `network_rtt_external`, `network_rtt_other_clusters`, `network_connectivity`, `network_tcp_connections`
- **Instances**: `instance_availability`, `instance_restarts`
- **Deployments**: `deployment_status`
- **Redis**: `redis_availability`, `redis_latency`
- **Mongodb**: `mongodb_availability`, `mongodb_replication_lag`
- **Memcached**: `memcached_availability`
- **Postgres**: `postgres_availability`, `postgres_latency`, `postgres_replication_lag`, `postgres_connections`
- **MySQL**: `mysql_availability`, `mysql_replication_status`, `mysql_replication_lag`, `mysql_connections`
- **Logs**: `log_errors`
- **JVM**: `jvm_availability`, `jvm_safepoint_time`
- **.NET**: `dotnet_availability`
- **Python**: `python_gil_waiting_time`
- **Node.js**: `nodejs_event_loop_blocked_time`
- **DNS**: `dns_latency`, `dns_server_errors`, `dns_nxdomain_errors`

Each inspector:
- Has a category (the report it contributes to).
- Has a type (event-based / item-based / value-based / manual) — determines how its message and condition are formatted.
- Has a default threshold and a unit (`percent`, `second`, `byte`, `seconds/second`, or none).
- Has message and condition templates, with placeholders for items, count, value, threshold.
- Is overridable per project (operator can set a custom threshold, or disable it).

### 4.11 Reports

- **Audit report** — a per-application or per-node report with a name (one of the check categories), a status, and a list of checks. Reports are grouped by category and rendered as the "audit" panel in the application/node detail view.

### 4.12 Dashboards and panels

- **Dashboard** — a named collection of panels, scoped to a project. Has id, name, panels (in order), created/updated timestamps.
- **Panel** — a single visualization on a dashboard. Has a query (a PromQL expression, a log query, a trace query, a top-N query, a flamegraph query, a heatmap query, a table query, or a "current incidents" view), a visualization kind, an axis configuration, a time range override.

---

## 5. Storage

The system uses three storage backends, with optional fourth (PostgreSQL alternative to SQLite) and fifth (Coroot Cloud).

### 5.1 Configuration database

**Backends**: SQLite (default) or PostgreSQL (optional). Selected at startup.

**Contents**: every durable entity that is not a time series — users, projects, integrations, alerting rules, dashboards, panels, applications (persisted metadata), incidents, alerts, notifications, deployments, custom applications, application categories, custom cloud pricing, check configurations, RBAC roles (Enterprise), SSO config (Enterprise), AI config (Enterprise), license state, settings key-value entries.

**Schema management**: a startup migration step applies all pending migrations. Migrations are auto-applied on first run; on subsequent runs, only the deltas are applied.

**Concurrency**: connection pool. A primary-lock primitive elects the active instance in a multi-instance deployment; non-primary instances do not run the inspection cycle or notification delivery.

**Connection**: SQLite is opened at `<data-dir>/coroot.db` by default; PostgreSQL is connected via a connection string.

**Notable semantics**:
- Migrations may include data backfills (e.g. migrating the SSO config from an old format to a new one).
- Schema differs slightly between Community and Enterprise: the Enterprise schema adds the `roles` table, the `sso_config` table, and the `ai_config` table.
- Alerts and incidents are stored in tables designed for time-range queries (so a list-alerts or list-incidents endpoint with a time filter is efficient).

### 5.2 Time-series cache

**On-disk format**: chunked time-series database, written under `<data-dir>/cache`. Prometheus-style series are stored with their labels and chunked values. Traces, logs, and profiles use a parallel chunk store.

**What's stored**:
- Metrics: per-series, per-chunk.
- Trace summaries: per-trace, per-chunk.
- Log indexes (pointers into ClickHouse or into the local log store).
- Profile metadata: per-profile, per-chunk.

**Retention**: a single TTL governs the cache; each project can have its own cache-TTL override. Default cache TTL is 30 days. Default per-signal TTLs (metrics, traces, logs, profiles) are 7 days each.

**Garbage collection**: a periodic GC runs at a configurable interval (default 10 minutes). The GC removes chunks whose end time is older than the TTL. The GC is locked in step with the primary-lock so that multiple instances do not race.

**Querying**: PromQL range queries are evaluated against the cache; series metadata, label names, and label values are served by the cache. For multi-cluster projects, the cache is queried per member project and the results are merged in the constructor.

**Write path**: the collector writes new chunks to the cache; on a successful write, the cache publishes an "update available" signal for the project.

### 5.3 ClickHouse (optional)

**When used**: when the operator has configured ClickHouse globally, per project, or as a bootstrap. The configuration is a host:port address, basic auth, database name, and optional TLS.

**Schemas** (high-level):
- Traces: a table per project (or shared) keyed by trace id, with span id, parent span id, service, name, kind, start/end times, attributes, status, events.
- Logs: a table per project (or shared) keyed by service and timestamp, with severity, message, attributes.
- Profiles: a table per project (or shared) keyed by service and timestamp, with profile type, sample value, stack-trace tree.

**Operations supported**: range queries on traces, logs, and profiles; full-text search on logs; sample extraction (sample trace id, sample error message); aggregations for top-N endpoints by error rate, etc.

**TTL**: ClickHouse's own TTL governs long-term storage; the cache's TTL governs what is in the warm path. ClickHouse is also a valid query backend for metrics in place of Prometheus (controlled by a "use ClickHouse" flag on the Prometheus integration).

**Connection mode**: per project, with a pool. For multi-cluster projects, the per-cluster connections are kept separate.

**Connect proxy**: the system exposes a CONNECT endpoint (`/api/clickhouse-connect`) that allows a node agent to establish a raw TCP connection to its project's ClickHouse through the system. This is how a node agent that does not have direct network access to ClickHouse can still reach it (via the system as a reverse proxy).

### 5.4 Prometheus (optional, as a query backend)

A Prometheus instance may be configured globally or per project. The system uses it as a metrics source: PromQL queries and label queries are forwarded to the Prometheus instance; the in-memory cache is not used in that path. The configuration includes URL, basic auth, extra selector (a label matcher to add to every query), custom headers, refresh interval, and TLS-skip-verify.

Prometheus remote write is also supported: the system can accept Prometheus remote-write requests on `/v1/metrics` and persist them in the local cache (so the operator can use the system as a Prometheus remote-write target).

### 5.5 Embedded assets

The single-page application (the web UI) is a Vue.js SPA. Its compiled assets (HTML, CSS, JS, fonts, images) are embedded in the binary and served from the `/static/` path. In development mode, the assets are served from the on-disk `./static` directory instead. The `index.html` template is rendered with the deployment-specific values: base path, version, instance UUID, update-check flag, edition name, cloud URL.

### 5.6 File system layout

The data directory has the following layout:

```
<data-dir>/
  coroot.db                       # SQLite configuration database
  instance.uuid                   # Instance UUID (generated on first start)
  cache/                          # Time-series cache
  cloud-pricing/                  # Cached cloud rate-card data
```

The instance UUID is generated on first startup and persisted. The deployment UUID is generated and stored in the configuration database on first startup; it is stable across restarts of the same deployment.

---

## 6. Configuration

The system is configured by a combination of:

- A **configuration file** (YAML), passed via `--config` / `CONFIG`.
- **Command-line flags**, each with a corresponding environment variable.
- **Defaults** baked into the binary.

The precedence is: defaults → config file → flags. Flags override config-file values; config-file values override defaults.

### 6.1 Server

| Flag | Env var | Default | Description |
|---|---|---|---|
| `--config` | `CONFIG` | _(unset)_ | Path to the YAML configuration file. |
| `--listen` | `LISTEN` | `:8080` | HTTP listen address (`ip:port` or `:port`). |
| `--https-listen` | `HTTPS_LISTEN` | _(unset)_ | HTTPS listen address. |
| `--http-disabled` | `HTTP_DISABLED` | `false` | Disable the plain-HTTP server. |
| `--grpc-listen` | `GRPC_LISTEN` | `:4317` (when not disabled) | gRPC/OTLP listen address. |
| `--grpc-disabled` | `GRPC_DISABLED` | `false` | Disable the gRPC server. |
| `--tls-cert-file` | `TLS_CERT_FILE` | _(unset)_ | Path to the TLS certificate (PEM). |
| `--tls-key-file` | `TLS_KEY_FILE` | _(unset)_ | Path to the TLS private key (PEM). |
| `--url-base-path` | `URL_BASE_PATH` | `/` | Mount the API under a sub-path. |
| `--data-dir` | `DATA_DIR` | `./data` | Path to the data directory. |
| `--developer-mode` | `DEVELOPER_MODE` | `false` | Serve the SPA from the on-disk `./static` directory. |

### 6.2 Storage

| Flag | Env var | Default | Description |
|---|---|---|---|
| `--pg-connection-string` | `PG_CONNECTION_STRING` | _(unset)_ | PostgreSQL connection string. If unset, SQLite is used. |
| `--cache-ttl` | `CACHE_TTL` | `30d` | Cache TTL (time-series). |
| `--cache-gc-interval` | `CACHE_GC_INTERVAL` | `10m` | Cache GC interval. |
| `--traces-ttl` | `TRACES_TTL` | `7d` | Traces TTL. |
| `--logs-ttl` | `LOGS_TTL` | `7d` | Logs TTL. |
| `--profiles-ttl` | `PROFILES_TTL` | `7d` | Profiles TTL. |
| `--metrics-ttl` | `METRICS_TTL` | `7d` | Metrics TTL. |

### 6.3 Global ClickHouse

| Flag | Env var | Description |
|---|---|---|
| `--global-clickhouse-address` | `GLOBAL_CLICKHOUSE_ADDRESS` | Address (`host:port`). |
| `--global-clickhouse-user` | `GLOBAL_CLICKHOUSE_USER` | Username. |
| `--global-clickhouse-password` | `GLOBAL_CLICKHOUSE_PASSWORD` | Password. |
| `--global-clickhouse-initial-database` | `GLOBAL_CLICKHOUSE_INITIAL_DATABASE` | Initial database. |
| `--global-clickhouse-tls-enabled` | `GLOBAL_CLICKHOUSE_TLS_ENABLED` | Enable TLS. |
| `--global-clickhouse-tls-skip-verify` | `GLOBAL_CLICKHOUSE_TLS_SKIP_VERIFY` | Skip TLS verification. |

### 6.4 Global Prometheus

| Flag | Env var | Description |
|---|---|---|
| `--global-prometheus-url` | `GLOBAL_PROMETHEUS_URL` | Prometheus URL. |
| `--global-prometheus-tls-skip-verify` | `GLOBAL_PROMETHEUS_TLS_SKIP_VERIFY` | Skip TLS verification. |
| `--global-refresh-interval` | `GLOBAL_REFRESH_INTERVAL` | Refresh interval. |
| `--global-prometheus-user` | `GLOBAL_PROMETHEUS_USER` | Basic-auth username. |
| `--global-prometheus-password` | `GLOBAL_PROMETHEUS_PASSWORD` | Basic-auth password. |
| `--global-prometheus-custom-headers` | `GLOBAL_PROMETHEUS_CUSTOM_HEADERS` | Custom headers (`Name=value`, repeatable). |
| `--global-prometheus-remote-write-url` | `GLOBAL_PROMETHEUS_REMOTE_WRITE_URL` | Remote-write URL. |
| `--global-prometheus-use-clickhouse` | `GLOBAL_PROMETHEUS_USE_CLICKHOUSE` | Use ClickHouse as the metrics query backend. |

### 6.5 Bootstrap

Bootstrap values are applied to the first-created (or only) project on first start.

| Flag | Env var | Description |
|---|---|---|
| `--bootstrap-prometheus-url` | `BOOTSTRAP_PROMETHEUS_URL` | Initial Prometheus URL. |
| `--bootstrap-refresh-interval` | `BOOTSTRAP_REFRESH_INTERVAL` | Initial refresh interval. |
| `--bootstrap-prometheus-extra-selector` | `BOOTSTRAP_PROMETHEUS_EXTRA_SELECTOR` | Extra label selector. |
| `--bootstrap-prometheus-remote-write-url` | `BOOTSTRAP_PROMETHEUS_REMOTE_WRITE_URL` | Initial remote-write URL. |
| `--bootstrap-prometheus-use-clickhouse` | `BOOTSTRAP_PROMETHEUS_USE_CLICKHOUSE` | Use ClickHouse. |
| `--bootstrap-clickhouse-address` | `BOOTSTRAP_CLICKHOUSE_ADDRESS` | Initial ClickHouse address. |
| `--bootstrap-clickhouse-user` | `BOOTSTRAP_CLICKHOUSE_USER` | Initial ClickHouse user. |
| `--bootstrap-clickhouse-password` | `BOOTSTRAP_CLICKHOUSE_PASSWORD` | Initial ClickHouse password. |
| `--bootstrap-clickhouse-database` | `BOOTSTRAP_CLICKHOUSE_DATABASE` | Initial ClickHouse database. |

### 6.6 Authentication

| Flag | Env var | Description |
|---|---|---|
| `--auth-anonymous-role` | `AUTH_ANONYMOUS_ROLE` | Disable authentication and assign one of `Admin`, `Editor`, `Viewer` to the anonymous user. |
| `--auth-bootstrap-admin-password` | `AUTH_BOOTSTRAP_ADMIN_PASSWORD` | Password for the default `Admin` user on first boot. |

### 6.7 Behavior toggles

| Flag | Env var | Description |
|---|---|---|
| `--do-not-check-for-deployments` | `DO_NOT_CHECK_FOR_DEPLOYMENTS` | Do not check for new deployments. |
| `--do-not-check-for-updates` | `DO_NOT_CHECK_FOR_UPDATES` | Do not check for new versions. |
| `--disable-usage-statistics` | `DISABLE_USAGE_STATISTICS` | Do not upload anonymous usage statistics. |
| `--disable-builtin-alerts` | `DISABLE_BUILTIN_ALERTS` | Disable all built-in alerting rules. |
| `--clickhouse-space-manager-disabled` | `CLICKHOUSE_SPACE_MANAGER_DISABLED` | Disable the ClickHouse space manager. |
| `--clickhouse-space-manager-usage-threshold` | `CLICKHOUSE_SPACE_MANAGER_USAGE_THRESHOLD` | Disk usage % threshold for the space manager. Default `70`. |
| `--clickhouse-space-manager-min-partitions` | `CLICKHOUSE_SPACE_MANAGER_MIN_PARTITIONS` | Min partitions to keep. Default `1`. |

### 6.8 License (Enterprise)

| Flag | Env var | Description |
|---|---|---|
| `--license-key` | `LICENSE_KEY` | The license key. |

The license key is also persisted in the configuration database after first validation, so it does not need to be re-supplied on every restart. The background license refresher (default: every few hours) re-validates it against the license service.

### 6.9 Configuration file shape (YAML)

The YAML configuration file has three top-level sections:

- **Server / global settings** — listen address, URL base path, data dir, auth, behavior toggles, server-side settings.
- **`projects`** — a list of project definitions. Each project has a name, member projects (for multi-cluster), API keys, integrations (notification integrations, base URL, slack/teams/pagerduty/opsgenie/webhook configs), application categories, custom applications, alerting rules (which mark the rule as readonly when loaded from config), and inspection overrides (per-application SLO availability and SLO latency objectives).
- **`global_clickhouse`** / **`global_prometheus`** / **`corootCloud`** — global integration settings.
- **`bootstrap_clickhouse`** / **`bootstrap_prometheus`** — values used to seed the first project on first boot.

A complete example shape (illustrative, fields abbreviated):

```yaml
listen_address: ":8080"
data_dir: "./data"
url_base_path: "/"
cache:
  ttl: 30d
  gc_interval: 10m
metrics: { ttl: 7d }
traces: { ttl: 7d }
logs: { ttl: 7d }
profiles: { ttl: 7d }

global_prometheus:
  url: "http://prometheus:9090"
  refresh_interval: 15s

projects:
  - name: "production"
    api_keys:
      - key: "..."
        description: "node-agent"
    notification_integrations:
      baseURL: "https://coroot.example.com"
      slack:
        token: "xoxb-..."
        defaultChannel: "alerts"
        incidents: true
        deployments: true
        alerts: true
    application_categories:
      - name: "Databases"
        custom_patterns:
          - "label:k8s.io/component in (postgres, mysql)"
    alerting_rules:
      - id: "high_cpu"
        severity: "warning"
        for: "5m"
```

---

## 7. Workflows

### 7.1 Startup sequence

On startup, the system (in this order):

1. Parses CLI flags and reads the configuration file.
2. Creates the data directory if it does not exist.
3. Opens the configuration database (SQLite or PostgreSQL) and runs migrations.
4. If the command is `set-admin-password`, prompts for and sets the default admin password, then exits.
5. Bootstraps global settings (Coroot Cloud, project definitions, application categories, custom applications, alerting rules, inspection overrides).
6. Generates or reads the instance UUID.
7. Reads or generates the deployment UUID.
8. Initializes the time-series cache.
9. Starts the gRPC server (if enabled).
10. Initializes the collector.
11. Initializes the cloud pricing manager.
12. Initializes the stats collector (no-op if `disable_usage_statistics`).
13. Initializes the license manager (Enterprise). The manager starts a background task that re-validates the license periodically.
14. Initializes the API. The API auth-init step reads or generates the `auth_secret` and creates the default admin user if it does not exist.
15. Initializes the incidents, deployments, and alerts watchers.
16. Starts the watcher loop. The loop listens for "data is fresh" signals from the cache, deduplicates them, acquires the primary lock, and runs the inspection cycle for each project that has fresh data. A ticker also drives multicluster projects (which are not cache-driven).
17. Registers MCP enterprise tools (Enterprise).
18. Registers HTTP routes.
19. Starts the gRPC server's accept loop.
20. Starts the HTTP / HTTPS listen loop.
21. Installs signal handlers (SIGINT, SIGTERM) that gracefully shut down the gRPC server and the collector before exiting.

### 7.2 Telemetry ingestion

The collector accepts four streams of telemetry on the HTTP and gRPC endpoints:

- **Metrics** — Prometheus remote-write format on `POST /v1/metrics`. Auth: `X-API-Key`. The request body is parsed as Prometheus remote-write protobuf; the resulting series are written to the cache.
- **Traces** — OTLP/HTTP on `POST /v1/traces`, and OTLP/gRPC on the gRPC `TraceService` server. The request body is OTLP `ExportTraceServiceRequest`; spans are written to the cache and (if configured) to ClickHouse.
- **Logs** — OTLP/HTTP on `POST /v1/logs`, and OTLP/gRPC on the gRPC `LogsService` server. The request body is OTLP `ExportLogsServiceRequest`; log records are written to the cache and (if configured) to ClickHouse.
- **Profiles** — on `POST /v1/profiles`. Auth: `X-API-Key`. The request body is a Coroot-specific profile payload.

For all four, the API key is resolved to a project (excluding multicluster projects; if the key does not match a known project, the request is rejected). The project is then associated with the request. The cache is written, and an "update available" signal is published for the project.

There is also a config-exchange endpoint (`GET/POST /v1/config`) where the agent can fetch its configuration and push back what it has observed (which is used to populate the agent's understanding of the project and to feed the constructor).

### 7.3 Inspection cycle

The inspection cycle is the core of the system. It runs:

- Whenever new data is available in the cache for a project (event-driven).
- For multicluster projects, on a periodic ticker (since the cache is per-cluster and the merge is project-level).
- A configurable minimum interval between runs (default: 15 seconds; the minimum is the project's Prometheus refresh interval, with a floor).

The cycle, per project:

1. **Construct the world** — read the cache for the project's time window, build a `World` value containing the topology (projects, applications, services, instances, nodes, containers, pods, volumes) and the relationships between them. For multicluster projects, the per-cluster worlds are merged.

2. **Run inspectors** — for each inspector in the catalog, evaluate the world. Each inspector produces a list of `Check` values, each with a status (`OK`, `WARNING`, `CRITICAL`, `UNKNOWN`).

3. **Aggregate into reports** — group checks by their category (CPU, Memory, Network, etc.). For each application, the categories form an audit report; the application has an overall status (worst-of-its-checks).

4. **Update alerts** — for each check that newly fires, create or update an alert. Alert identity is keyed by the check fingerprint (project + application + check id + window), so the same alert is updated (not re-created) on subsequent firings. An alert is considered resolved when its check transitions back to OK for the configured `keep_firing_for` window.

5. **Update incidents** — for each application, the open alerts are the basis of an incident. An incident is opened when the first alert fires for the application in a window; subsequent alerts in the same window are grouped into the same incident. An incident is resolved when all its alerts are resolved.

6. **Dispatch notifications** — for each new or updated alert, look up the matching alerting rule and dispatch to the configured notification channels (Slack, Teams, PagerDuty, Opsgenie, Webhook). For each incident, do the same for incident notifications. Deduplication and grouping are handled by the notification subsystem.

7. **Detect deployments** — for each application, check for a new deployment event (k8s rollout, Argo CD sync, Flux release, manual). If a new deployment is detected, record it in the application's deployment list and dispatch a deployment notification.

8. **Optionally run RCA** — for each open incident, the system may invoke the AI-driven RCA subsystem. The invocation is triggered by the user opening the incident detail page (or by an external MCP client calling the `get_incident_details` tool with `run_rca` set). The result is persisted on the incident.

9. **Update the configuration database** — persist incidents, alerts, and notifications as required for the API to serve them.

### 7.4 Alerting

#### Rule evaluation

Alerting rules produce alerts. Each rule has:

- A source: a check (fires when the check fires), a PromQL expression (fires when the expression returns a non-empty result, with a configurable condition and threshold), a log-pattern (fires when the configured severity filters match), or a k8s-event (fires when the configured event kind happens).
- A selector: which applications the rule applies to (a label match).
- A severity: `warning` or `critical`.
- `for`: a duration; the condition must hold for at least this long before the alert fires.
- `keep_firing_for`: a duration; after the condition clears, the alert continues to be reported as firing for this long (used to deduplicate).
- Templates: optional summary / description templates with placeholders.
- Notification category: an optional application category for routing.
- Enabled flag.
- Readonly flag (set when the rule was loaded from the configuration file).

Built-in rules exist by default. The `disable_builtin_alerts` flag disables them at startup. User-defined rules are stored in the configuration database.

#### Deduplication and grouping

An alert's fingerprint is computed from its identifying attributes (project, application, check id or rule id, and a few others). When a new alert would be created with the same fingerprint as an existing one, the existing alert is updated. An alert can be manually resolved, suppressed, or re-opened. Suppressed alerts are not re-sent but remain in the database; manually-resolved alerts can be re-opened if the underlying condition re-asserts.

Incidents group alerts by application and time window. An incident has a unique key (project + application + window start); all alerts for the same application in the same window are part of the same incident.

#### SLO burn-rate alerting

The SLO inspectors use a multi-window burn-rate model. Two alert rules are defined by default for SLOs:

- Long window `1h` + short window `5m` with a burn-rate threshold of 14.4× → `CRITICAL`.
- Long window `6h` + short window `30m` with a burn-rate threshold of 6× → `CRITICAL`.

The SLO inspectors evaluate the SLI over both windows; if both windows are above the burn-rate threshold, the SLO is considered failing and the corresponding check fires.

### 7.5 Notification delivery

When an alert or incident is created or updated, the notifications subsystem:

1. Looks up the project's configured notification integrations.
2. For each enabled destination (per type), creates a client.
3. Calls the client's `SendAlert` or `SendIncident` method.
4. Persists the result (sent / not-sent) in the configuration database.
5. Retries undelivered notifications on a periodic basis (default: every minute, within a one-hour retry window).

Each channel has a small dedicated client:

- **Slack** — uses Slack Web API; the message is a Block Kit payload with summary, status, link to the incident / alert, and per-check details.
- **MS Teams** — uses the configured webhook URL; the message is a Microsoft Adaptive Card with the same fields.
- **PagerDuty** — uses the PagerDuty Events v2 API; the event is a `trigger` (when firing) or `resolve` (when resolved), with a `DedupKey` derived from the alert / incident external key.
- **Opsgenie** — uses Opsgenie Alerts API; the alert is created with a description, severity, and tags.
- **Webhook** — generic JSON; the payload is templated using the operator's template strings. Basic auth, custom headers, and custom fields are merged into the request.

A deployment notification is also supported for the channels that accept it (Slack, Teams, Webhook; PagerDuty and Opsgenie do not support deployment notifications).

### 7.6 RCA — root-cause analysis (Enterprise)

The RCA subsystem, when invoked for an incident:

1. **Gather signals** for the incident's time window:
   - Deployments detected during the window.
   - Application / integration configuration changes.
   - Kubernetes events.
   - Log patterns (top error patterns, top new patterns).
   - Profiles (CPU, memory, allocation, inuse, query) — diff against a baseline.
   - Traces — full sample traces for the affected endpoints.
   - Related metrics (other signals in the same time window that correlate with the failing SLI).
2. **Build a prompt** — assemble the signals into a structured prompt with:
   - A system message describing the analyst's role.
   - A summary of the problem.
   - A correlation chart of the relevant metrics over the window.
   - A list of related log errors and patterns.
   - A diff of CPU and memory profiles.
   - Step-by-step reasoning.
3. **Call the AI provider** — based on the configured provider (Anthropic, OpenAI, or OpenAI-compatible), call the corresponding API with the prompt and a structured-output schema.
4. **Parse the response** into a structured RCA report:
   - Problem statement.
   - Root cause(s).
   - Immediate fixes.
   - Related log errors.
   - Related metrics (with a chart).
   - Propagation map (which applications are affected upstream and downstream).
5. **Cache the report on the incident** so subsequent requests do not re-invoke the AI provider unless the time window changes.

The RCA subsystem is rate-limited per project (a configurable cap on requests per hour) and consumes license quota.

### 7.7 Anomaly detection (Enterprise)

A separate anomaly-detection subsystem runs continuously:

1. For each metric, maintain a statistical baseline (e.g. weekly / daily seasonality, mean, variance).
2. When a metric's recent value deviates from the baseline by more than a threshold, flag an anomaly.
3. Optionally, call the AI provider to produce a human-readable explanation of the anomaly. The explanation is cached.
4. Anomalies are listed and investigated via the MCP tool `list_anomalies` and the API endpoints `/api/project/{project}/anomalies` and `/api/project/{project}/anomalies/{anomaly}`.

### 7.8 User authentication

The system supports two authentication paths:

- **Local** — the user provides email + password to the login endpoint. The password is verified against a bcrypt hash in the configuration database. On success, a session cookie is issued.
- **SSO (Enterprise)** — the user clicks an SSO link. The system redirects to the configured OIDC or SAML provider. The user authenticates with the provider. The provider redirects back to the system with an authorization code (OIDC) or an assertion (SAML). The system exchanges the code for a user profile (OIDC) or parses the assertion (SAML), maps claims to user attributes, finds or creates a local user, and issues a session cookie.

The first-boot flow is special: the system has no users, so the first call to the login endpoint is treated as a `set_admin_password` action — the operator sets the admin password and a session cookie is issued.

Once authenticated, every request is mapped to a `User` value with a list of role names. RBAC checks are applied per request based on the action being performed.

### 7.9 License validation (Enterprise)

The license manager:

1. On startup, reads the license key from the configuration (file, env, or DB-cached).
2. Validates the key against the Coroot Cloud license service (a `POST /licenses/validate` endpoint at the cloud URL). The request includes the key and the deployment's identifying information. The response includes the license status, expiry, tier, allowed features, used quota, and grace-period.
3. Persists the validated state in the configuration database.
4. Starts a background task that re-validates the license on a periodic basis (every few hours).
5. Exposes `CheckLicense()` to the rest of the system. Calls to `CheckLicense()` are used to gate Enterprise-only features (RCA, anomaly explanation, custom roles, SSO). If the license is invalid or expired and the grace period has passed, the system continues to function in Community mode (or refuses to start, depending on configuration).

The license key is the only thing the operator needs to provide. Once validated, the binary operates locally; subsequent license checks happen on a timer.

---

## 8. Security model

### 8.1 Authentication matrix

| Surface | Auth mechanism | How to authenticate |
|---|---|---|
| HTTP API (UI) | Session cookie | Login with email + password (or SSO); receive a `Set-Cookie` for `coroot_session`. |
| HTTP API (collector) | API key | Send `X-API-Key: <key>` header. |
| HTTP API (MCP) | OAuth bearer | Obtain an access token via the OAuth 2.0 authorization code + PKCE flow; send `Authorization: Bearer <jwt>`. |
| gRPC (OTLP) | API key | Send `X-API-Key: <key>` as gRPC metadata. |
| OIDC SSO | Authorization code | Redirect to OIDC provider; receive code; exchange for user profile. |
| SAML SSO | HTTP POST | Receive SAML assertion at the ACS URL; parse and validate. |

### 8.2 Authorization (RBAC)

- A user has one or more roles.
- Each role has a list of permissions, each a `(scope, verb, object)` triple.
- A request is allowed if any of the user's roles grants the action.
- Object matchers use glob (`*`) so a single permission can apply to many resources (e.g. all applications in a project).
- The Enterprise tier adds custom roles stored in the configuration database, with the same permission model.

Built-in roles:
- `Admin` — every permission, every scope.
- `Editor` — every read permission + a defined set of edit permissions per project (custom applications, application categories, inspections, custom cloud pricing, dashboards, alerting rules, alerts, risks).
- `Viewer` — every read permission.

### 8.3 Secrets

- **Session cookie secret (`auth_secret`)** — auto-generated on first startup, stored in the configuration database setting. Used for HMAC-SHA256 signing of session cookies and JWTs.
- **License key** — supplied via flag/env/config. Cached in the configuration database after first validation.
- **Integration tokens** — stored in the per-project integration settings. Treated as opaque secrets; not echoed back to non-editor users.
- **Database connection strings** — supplied via flag/env/config; not persisted in plaintext.
- **TLS private keys** — supplied via flag/env/config; not persisted.

A re-implementation should follow the same principle: secrets are stored in the configuration database with the same access controls as the rest of the configuration (i.e. not readable by unauthenticated users).

### 8.4 SSRF boundary

The system can be configured to make outbound requests to user-supplied URLs in two paths:

- **Webhook notifications** — the operator supplies a webhook URL.
- **Prometheus remote write** — the operator supplies a remote-write URL.

These are SSRF-sensitive because the operator can point them at internal addresses. The system does not (in its current form) validate the URL against a deny-list. A re-implementation should consider:

- An optional deny-list of internal IP ranges and metadata endpoints.
- An optional allow-list configured by the operator.
- A `DISABLE_WEBHOOK_URL_VALIDATION` env var (which the binary advertises) — i.e. validation is on by default but can be disabled.

The ClickHouse connect endpoint is a CONNECT proxy that takes a hijacked HTTP connection and proxies it as raw TCP to the project's ClickHouse address; it is not user-controlled in the same way.

### 8.5 Session cookie

- Name: `coroot_session`.
- Attributes: `Path=/`, `HttpOnly=true`, `Expires=<now + 7 days>`.
- Signing: HMAC-SHA256 (HS256-equivalent) over the payload, with a server-side secret.
- Payload: opaque to the user; contains the user identifier.
- Logout: clears the cookie (no `Expires`).

A re-implementation should additionally set the `Secure` and `SameSite` attributes when serving over HTTPS, to harden against cross-site attacks.

### 8.6 MCP token

- Format: JWT.
- Signing: HS256 with the same server-side secret as the session cookie.
- Audience: `mcp:access` for access tokens; `mcp:code` for authorization codes; `mcp:refresh` for refresh tokens; `mcp:client` for dynamic client registrations.
- TTL: 1 hour for access tokens; 30 seconds for authorization codes; 30 days for refresh tokens.
- The token's signature is verified; the audience is checked.

### 8.7 Known security considerations

The following items are documented as behavioral contract (i.e. the system as observed does or does not do these) so a re-implementation can decide on each:

| Item | Observation in target system | Recommended re-implementation posture |
|---|---|---|
| gRPC receive message size | Set to the maximum integer. | Set a reasonable limit (e.g. 16 MiB) at the application layer, and/or enforce a limit at the network/proxy layer. |
| `/debug/pprof/` | Exposed on the same listener as the public API. | Bind pprof to a private interface, gate it behind authentication, or disable it in production. |
| Session cookie `Secure` and `SameSite` | Not set by default. | Set `Secure` and `SameSite=Lax` (or stricter) when serving over HTTPS. |
| Webhook / remote-write URL validation | Not enforced by default. | Provide a configurable deny-list and/or allow-list; document the failure mode. |
| Dependency vulnerabilities | The target system ships with several known-vulnerable transitive dependencies (gRPC, JWT, JOSE, SAML, Prometheus). | Re-implementations should pin current versions and run an OSV (or equivalent) scan as part of the build pipeline. |
| OAuth revoke | The revoke endpoint is a no-op. | Implement server-side revocation tracking or document that JWTs are valid until expiry. |

---

## 9. Integrations

### 9.1 Notification channels

| Channel | Protocol | Auth | Payload shape (high level) | Deployment notifications |
|---|---|---|---|---|
| Slack | Slack Web API | Bot token | Block Kit message with summary, status, link, per-check details. | Yes |
| MS Teams | Incoming webhook | Webhook URL | Adaptive Card with summary, status, link, per-check details. | Yes |
| PagerDuty | Events API v2 | Integration key | `trigger` / `resolve` event with `DedupKey`, summary, severity, source, timestamp, details. | No |
| Opsgenie | Alerts API | API key (US or EU endpoint) | Alert with description, severity, tags, source. | No |
| Webhook | HTTP POST (templated) | Optional basic auth, custom headers | Operator-supplied template strings; custom fields are merged in. | Yes |

### 9.2 AI providers (Enterprise)

| Provider | API | Required config | Notes |
|---|---|---|---|
| Anthropic | Messages API | API key, model name (e.g. `claude-opus-4-8`), optional base URL. | Used for RCA and anomaly explanation. |
| OpenAI | Chat Completions | API key, model name. | Used for RCA and anomaly explanation. |
| OpenAI-compatible | OpenAI Chat Completions | Base URL, API key (optional), model name. | Used for self-hosted or alternative providers. |

A re-implementation can support any subset; the contract is that the system has a pluggable "call the LLM with a structured prompt and parse the response into a structured RCA report" interface.

### 9.3 Telemetry sinks

| Sink | Protocol | Auth | Role |
|---|---|---|---|
| Prometheus remote write | `application/x-protobuf` with snappy compression | None (the system is the receiver) | Receives metrics from external Prometheus instances. |
| OTLP/HTTP traces | OTLP `ExportTraceServiceRequest` JSON or protobuf | API key (`X-API-Key`) | Receives traces. |
| OTLP/HTTP logs | OTLP `ExportLogsServiceRequest` JSON or protobuf | API key (`X-API-Key`) | Receives logs. |
| OTLP/gRPC traces | OTLP `ExportTraceServiceRequest` protobuf | API key (gRPC metadata) | Receives traces. |
| OTLP/gRPC logs | OTLP `ExportLogsServiceRequest` protobuf | API key (gRPC metadata) | Receives logs. |
| Profile payload | Coroot-specific protobuf | API key (`X-API-Key`) | Receives profiles from the node agent. |

### 9.4 Identity providers (Enterprise)

| Provider | Protocol | Required config |
|---|---|---|
| OIDC | OAuth 2.0 / OIDC authorization code | Issuer URL, client ID, client secret, claim mapping (which claim is the user email / name). |
| SAML 2.0 | HTTP POST binding | Metadata XML (or fields: entity ID, SSO URL, optional signing/encryption certs), attribute mapping (which attribute is the user email / name). |

### 9.5 Cloud providers (cost data)

The system uses a published rate-card dataset (not direct cloud APIs) to compute cost estimates. The rate-card is downloaded from a Coroot-maintained URL:

- `https://coroot.github.io/cloud-pricing/data/cloud-pricing.json.gz`

The rate card contains per-resource prices (CPU per core per hour, memory per GB per hour, network egress per GB) by region and instance type. The system caches it locally and re-downloads periodically.

The AWS integration is used to discover RDS and ElastiCache instances (so they can be priced). The configuration is region + access key + secret key + optional tag filters.

### 9.6 Coroot Cloud

Optional SaaS connection. The configuration is a single API key and a boolean `incidents_auto_investigation` flag. Used for:

- License validation.
- Optional version-update check.
- Optional anonymous usage statistics.

If disabled, the system is fully functional offline.

---

## 10. Operational considerations

### 10.1 Deployment topology

A single instance of the binary serves one or more projects. A typical deployment is:

- One instance per region / availability zone, active/standby.
- The active instance is elected via the configuration database lock.
- Only the active instance runs the inspection cycle and notification delivery.
- The HTTP and gRPC servers can serve traffic from either instance; non-primary instances serve read traffic and accept telemetry, but the inspection cycle is paused.

For high availability, the system assumes a network-accessible shared database (PostgreSQL is more appropriate than SQLite for multi-instance deployments).

### 10.2 K8s deployment

The system ships a Helm chart (`coroot`) that deploys:

- A stateful set for the server (with a persistent volume for the data directory).
- A service for the HTTP / HTTPS / gRPC ports.
- A service account and RBAC for the node agent (which is a separate component that scrapes pods and forwards telemetry).

In a K8s deployment, the recommended storage is PostgreSQL (via a managed service) and ClickHouse (via a managed service or a clickhouse-operator-managed stateful set). The data directory on the persistent volume is still used for the time-series cache and cloud-pricing cache.

### 10.3 Backup and restore

The configuration database is the only durable state that must be backed up. The time-series cache and ClickHouse are recoverable from the upstream sources; the cloud-pricing cache is re-downloadable. To back up the configuration database, take a snapshot of the SQLite file (if SQLite) or a `pg_dump` (if PostgreSQL). The `instance_uuid` and `deployment_uuid` are stable across restarts and should be preserved.

To restore, point a fresh instance at the restored database; it will read the existing users, projects, integrations, alerts, incidents, and notifications. The time-series cache will rebuild from incoming telemetry.

### 10.4 Scaling

The system is not horizontally scalable for the inspection cycle; that runs on a single instance. The HTTP and gRPC ingestion paths can be load-balanced across multiple instances, with the caveat that the inspection cycle only runs on the primary.

Per-project scale limits (rough, from observed behavior):
- A project can hold tens of thousands of time series without issue.
- A project can hold hundreds of applications and thousands of instances.
- The cache TTL is the main knob for disk usage: 30 days × N series × Y bytes per sample.
- ClickHouse scales independently; the system assumes ClickHouse is sized appropriately for the operator's data retention requirement.

### 10.5 Observability

The system itself exposes a `/health` endpoint for liveness checks. The gRPC server can be monitored with standard gRPC tooling. The `/stats` endpoint is used internally for opt-in anonymous usage statistics; operators can also use it to read the same data for their own purposes.

### 10.6 Version updates

If the `do_not_check_for_updates` flag is not set, the system checks the Coroot Cloud version endpoint on a periodic basis. When a new version is available, a notification is shown in the UI. Operators can disable the check.

### 10.7 License state

The license state is reflected in the UI (a banner). The system continues to operate in Community mode if the license is missing or invalid, with the Enterprise features disabled. There is no hard failure mode tied to license expiry in normal operation.

### 10.8 Data directory

The data directory contains:

- The configuration database (SQLite file, if SQLite is the backend).
- The `instance.uuid` file (a single UUID line).
- The `cache/` subdirectory (time-series cache).
- The `cloud-pricing/` subdirectory (cached rate cards).

Operators should back up the data directory regularly. The data directory should be on a filesystem that supports the size required for the cache TTL × per-series volume.

---

## 11. Reference: subsystem-to-package correspondence (informational)

This appendix is for the awareness of the re-implementation team only. It maps the public subsystems described in this specification to the (private) internal package structure of the target system. It is included to make the scope of each subsystem clearer, not as a recommendation about how to organize a re-implementation.

| Subsystem | Internal package(s) |
|---|---|
| HTTP API (Community) | `github.com/coroot/coroot/api` |
| HTTP API (Enterprise extensions) | `github.com/coroot/enterprise/api` |
| gRPC / OTLP | `github.com/coroot/coroot/grpc` |
| Collector (ingest) | `github.com/coroot/coroot/collector` |
| Time-series cache | `github.com/coroot/coroot/cache` |
| ClickHouse integration | `github.com/coroot/coroot/clickhouse`, `github.com/coroot/coroot/ch` |
| Constructor (world model) | `github.com/coroot/coroot/constructor` |
| Auditor (inspections) | `github.com/coroot/coroot/auditor` |
| Watchers | `github.com/coroot/coroot/watchers` |
| Notifications | `github.com/coroot/coroot/notifications` |
| Stats | `github.com/coroot/coroot/stats` |
| Cloud pricing | `github.com/coroot/coroot/cloud-pricing` |
| Coroot Cloud | `github.com/coroot/coroot/cloud` |
| Configuration | `github.com/coroot/coroot/config` (Community) / `github.com/coroot/enterprise/config` (Enterprise) |
| Configuration DB | `github.com/coroot/coroot/db` (Community) / `github.com/coroot/enterprise/db` (Enterprise) |
| Domain model | `github.com/coroot/coroot/model` |
| RBAC | `github.com/coroot/coroot/rbac` |
| License (Enterprise) | `github.com/coroot/enterprise/licenses` |
| RCA (Enterprise) | `github.com/coroot/enterprise/rca` |

The Enterprise binary is the Community binary plus the five `enterprise/*` packages. All Community functionality is also present in the Enterprise binary.

---

## 12. Acceptance criteria for a re-implementation

A re-implementation is considered functionally compatible if, at a minimum, it satisfies the following:

1. It exposes the same set of HTTP routes, with the same authentication requirements, and returns responses in the same shape as the target system.
2. It accepts the same telemetry inputs (Prometheus remote write for metrics; OTLP for traces, logs; Coroot-profile payloads for profiles) on the same endpoints, and processes them through a cache that supports the same PromQL query surface.
3. It implements the inspection cycle for the same catalog of checks, with the same defaults, and produces alerts and incidents with the same lifecycle.
4. It supports the same notification channels with the same payload shapes and the same delivery semantics.
5. It supports the same configuration surface (file format, flags, env vars) with the same defaults.
6. It supports the same storage backends (SQLite, PostgreSQL, ClickHouse, Prometheus) with the same schema and migration semantics.
7. It implements the same RBAC model with the same permission scopes, and the same set of built-in roles.
8. (Enterprise) It implements the same SSO flows (OIDC, SAML) with the same login → session-cookie sequence.
9. (Enterprise) It implements the same RCA flow (signal gathering → AI provider call → structured report).
10. (Enterprise) It implements license validation against the Coroot Cloud license service and gates Enterprise features on the result.
11. (Enterprise) It implements the same MCP tool surface and the same tool behavior.

Items 1–7 are required for a "Community-compatible" re-implementation; items 8–11 are required for "Enterprise-compatible".

---

## 13. Open items and follow-ups

The following items are not fully specified by this document and should be resolved during the re-implementation:

- **Field-level JSON shapes** for the API requests and responses. The current document specifies the methods, paths, and high-level semantics, but not the exact field names of request and response bodies. A re-implementation can either reverse-engineer these from observed API calls or design a new shape that satisfies the same contract. (Including field-level shapes here would conflict with the clean-room principle.)
- **Concrete inspector thresholds and conditions.** The current document lists the inspector catalog and the default thresholds, but the exact condition formulas (e.g. the multi-window burn-rate calculation for SLOs) are described at the contract level. A re-implementation can choose any implementation that produces the same observable behavior.
- **Database schema details.** The current document describes the storage backends and the conceptual schema, but not the exact column types, indexes, or constraints. A re-implementation can choose any schema that supports the same queries.
- **Default cloud-pricing dataset URL and format.** The current document mentions the URL but not the JSON structure. A re-implementation that wants to support cost estimates can adopt the same URL and format, or design its own.
- **MCP tool argument schemas.** The current document lists the tools and their purposes, but not the exact JSON Schema for each tool's parameters. A re-implementation can choose any schema that satisfies the same intent.

For each of these, the recommended approach is to either:
1. Reference the target system's behavior via observed API calls (the public API is the source of truth for compatibility), or
2. Design a new shape that is more amenable to the re-implementation's technology choices, document the delta, and accept the compatibility cost.
