# Coroot EE Binary Static Analysis Report

Target: `/Users/itsmac/Documents/Binary/coroot-ee`  
Analysis time: 2026-06-13, Asia/Ho_Chi_Minh  
Scope: static analysis only. The Linux ARM64 binary was not executed.

## 1. Executive summary

- Binary is a Go Linux ARM64 ELF executable for `github.com/coroot/enterprise`, version injected as `main.version=1.22.0`.
- It is dynamically linked, not stripped, and contains Go symbols, source paths, `.gopclntab`, `.go.buildinfo`, and DWARF debug info.
- Full inventory extracted:
  - 237,234 printable strings.
  - 992 unique URLs.
  - 8,633 path candidates.
  - 2,742 source file paths.
  - 69 high-confidence HTTP/API routes.
  - 47 Grype dependency vulnerability rows: 10 Critical, 14 High, 20 Medium, 3 Low.
  - 4 govulncheck symbol-level vulnerabilities that the binary appears to include/call.
- Secret scan did not find real AWS/GitHub/Slack/Google/OpenAI/Anthropic/JWT/basic-auth URL tokens. It did find 3 embedded PEM blocks, including one `RSA PRIVATE KEY` block that requires source/build verification.
- Static malware scan did not find direct process-spawn imports, Go `os/exec` symbols, miner/C2 indicators, or persistence behavior. `dlopen`/`dlsym` exist and appear consistent with CGO/dynamic library usage.
- Local security concerns found in the route surface:
  - `/debug/pprof/` is registered without app auth in the OSS v1.22.0 route layout.
  - `/stats` GET/POST are unauthenticated in the OSS v1.22.0 route layout and can expose/reset usage/infrastructure counters.

## 2. Tooling used

Installed/used tools:

- GoReSym `v1.7.1`
- redress `v1.2.74`
- govulncheck `v1.3.0`
- syft `1.45.1`
- grype `0.114.0`
- rizin `0.8.2`
- GNU binutils `2.46.1`
- yara `4.5.5`
- Go `1.26.1`

Tool environment file:

- `/Users/itsmac/Desktop/auto-scan-vuln-lic/analysis/coroot-ee/tool-env.sh`

## 3. Binary structure

| Field | Value |
|---|---|
| File | `/Users/itsmac/Documents/Binary/coroot-ee` |
| Size | `75,105,928` bytes |
| SHA256 | `8897486973706d2850f9ec8fbc8767d0dadce96983502ce7c047ebd35487813d` |
| Format | ELF64 LSB executable |
| Architecture | ARM AArch64 / Linux |
| Interpreter | `/lib/ld-linux-aarch64.so.1` |
| Build ID | `3c3b892fcaa374294cf2cdbefde27ebbfc5d5987` |
| Entry point | `0x402c00` |
| Go version | `go1.25.11` |
| Main module/path | `github.com/coroot/enterprise` |
| Version ldflag | `-X main.version=1.22.0` |
| CGO | enabled |
| Stripped | false |
| Debug info | present |
| PIE | false |
| NX | true |
| RELRO | partial |
| Stack canary | not reported by rizin |
| Dynamic libraries | `liblz4.so.1`, `libc.so.6` |

Important sections/symbol material:

- `.text`, `.rodata`, `.data`, `.bss`
- `.gopclntab`, `.go.buildinfo`, `.noptrdata`, `.typelink`, `.itablink`
- `.debug_info`, `.debug_line`, `.debug_abbrev`, `.debug_str`, `.debug_loclists`, `.debug_rnglists`
- `.symtab` and source path information are present.

Go package summary from redress:

- `# main`: 6
- `# std`: 188
- `# vendor`: 886
- `GoRoot`: `/usr/local/go`
- `Main root`: `/tmp/src`

Enterprise-specific symbols present:

- `github.com/coroot/enterprise/api.(*Api).AI`
- `github.com/coroot/enterprise/api.(*Api).IncidentRCA`
- `github.com/coroot/enterprise/api.(*Api).User`
- `github.com/coroot/enterprise/api.(*Api).Roles`
- `github.com/coroot/enterprise/api.(*Api).RCA`
- `github.com/coroot/enterprise/api.(*Api).Anomalies`
- `github.com/coroot/enterprise/api.(*Api).RegisterMCPEnterpriseTools`
- `github.com/coroot/enterprise/api.(*Api).OIDCCallback`
- `github.com/coroot/enterprise/api.(*Api).SamlACS`
- `github.com/coroot/enterprise/api.(*Api).Login`
- `github.com/coroot/enterprise/api.(*Api).SSO`
- `github.com/coroot/enterprise/api.(*Api).SSOStatus`
- `github.com/coroot/enterprise/api.(*Api).SSOLogin`
- `github.com/coroot/enterprise/licenses.NewManager`
- `github.com/coroot/enterprise/licenses.(*Manager).CheckLicense`
- `github.com/coroot/enterprise/licenses.(*Manager).validate`

## 4. Full extracted inventories

The complete lists are stored as TSV/TXT/JSON artefacts:

| Inventory | Count | File |
|---|---:|---|
| High-confidence API/HTTP routes | 69 | `/Users/itsmac/Desktop/auto-scan-vuln-lic/analysis/coroot-ee/full-inventory/api-routes-final.tsv` |
| OSS source route extraction | 71 | `/Users/itsmac/Desktop/auto-scan-vuln-lic/analysis/coroot-ee/full-inventory/api-routes-source-oss.tsv` |
| Candidate routes from binary | 553 | `/Users/itsmac/Desktop/auto-scan-vuln-lic/analysis/coroot-ee/full-inventory/api-routes-binary-clean.tsv` |
| All URL strings | 992 | `/Users/itsmac/Desktop/auto-scan-vuln-lic/analysis/coroot-ee/full-inventory/urls-all.tsv` |
| All path candidates | 8,633 | `/Users/itsmac/Desktop/auto-scan-vuln-lic/analysis/coroot-ee/full-inventory/paths-all-candidates.tsv` |
| Source file paths | 2,742 | `/Users/itsmac/Desktop/auto-scan-vuln-lic/analysis/coroot-ee/full-inventory/source-file-paths-all.txt` |
| SBOM | n/a | `/Users/itsmac/Desktop/auto-scan-vuln-lic/analysis/coroot-ee/full-inventory/syft-sbom.txt` |
| SBOM JSON | n/a | `/Users/itsmac/Desktop/auto-scan-vuln-lic/analysis/coroot-ee/full-inventory/syft-sbom.json` |
| govulncheck binary output | 4 direct findings | `/Users/itsmac/Desktop/auto-scan-vuln-lic/analysis/coroot-ee/full-inventory/govulncheck-binary.txt` |
| Grype output | 47 rows | `/Users/itsmac/Desktop/auto-scan-vuln-lic/analysis/coroot-ee/full-inventory/grype.txt` |
| Secret scan | 3 findings | `/Users/itsmac/Desktop/auto-scan-vuln-lic/analysis/coroot-ee/full-inventory/secret-scan.tsv` |
| Malware indicator scan | n/a | `/Users/itsmac/Desktop/auto-scan-vuln-lic/analysis/coroot-ee/full-inventory/malware-indicators.tsv` |

## 5. High-confidence API and HTTP routes

Routes below are either corroborated from Coroot OSS v1.22.0 route setup or inferred from enterprise symbols plus matching binary strings.

| Methods | Path | Notes |
|---|---|---|
| `*` | `/debug/pprof/` | Debug pprof route |
| `GET` | `/health` | Healthcheck |
| `*` | `/v1/metrics` | Collector |
| `*` | `/v1/traces` | Collector |
| `*` | `/v1/logs` | Collector |
| `*` | `/v1/profiles` | Collector |
| `*` | `/v1/config` | Collector |
| `POST` | `/api/login` | Login |
| `POST` | `/api/logout` | Logout |
| `GET,POST` | `/api/user` | Auth-wrapped |
| `GET,POST` | `/api/users` | Auth-wrapped |
| `GET,POST` | `/api/roles` | Auth-wrapped |
| `GET,POST` | `/api/sso` | Auth-wrapped |
| `GET,POST` | `/api/ai` | Auth-wrapped |
| `GET,POST` | `/api/cloud` | Auth-wrapped |
| `GET,POST` | `/api/project/` | Auth-wrapped |
| `GET,POST,DELETE` | `/api/project/{project}` | Auth-wrapped |
| `GET` | `/api/project/{project}/status` | Auth-wrapped |
| `GET,POST` | `/api/project/{project}/api_keys` | Auth-wrapped |
| `GET` | `/api/project/{project}/overview/{view}` | Auth-wrapped |
| `GET` | `/api/project/{project}/incidents` | Auth-wrapped |
| `GET` | `/api/project/{project}/incident/{incident}` | Auth-wrapped |
| `GET` | `/api/project/{project}/alerts` | Auth-wrapped |
| `POST` | `/api/project/{project}/alerts/resolve` | Auth-wrapped |
| `POST` | `/api/project/{project}/alerts/suppress` | Auth-wrapped |
| `GET` | `/api/project/{project}/alerts/{alert}` | Auth-wrapped |
| `POST` | `/api/project/{project}/alerts/reopen` | Auth-wrapped |
| `GET,POST` | `/api/project/{project}/alerting-rules` | Auth-wrapped |
| `GET` | `/api/project/{project}/alerting-rules/export` | Auth-wrapped |
| `GET,PUT,DELETE` | `/api/project/{project}/alerting-rules/{rule}` | Auth-wrapped |
| `GET,POST` | `/api/project/{project}/dashboards` | Auth-wrapped |
| `GET,POST` | `/api/project/{project}/dashboards/{dashboard}` | Auth-wrapped |
| `GET` | `/api/project/{project}/panel/data` | Auth-wrapped |
| `GET` | `/api/project/{project}/inspections` | Auth-wrapped |
| `GET,POST` | `/api/project/{project}/application_categories` | Auth-wrapped |
| `GET,POST` | `/api/project/{project}/custom_applications` | Auth-wrapped |
| `GET,POST,DELETE` | `/api/project/{project}/custom_cloud_pricing` | Auth-wrapped |
| `GET,PUT` | `/api/project/{project}/integrations` | Auth-wrapped |
| `GET,PUT,DELETE,POST` | `/api/project/{project}/integrations/{type}` | Auth-wrapped |
| `GET` | `/api/project/{project}/app/{app}` | Auth-wrapped |
| `GET` | `/api/project/{project}/app/{app}/rca` | Auth-wrapped |
| `GET,POST` | `/api/project/{project}/app/{app}/inspection/{type}/config` | Auth-wrapped |
| `GET,POST` | `/api/project/{project}/app/{app}/instrumentation/{type}` | Auth-wrapped |
| `GET,POST` | `/api/project/{project}/app/{app}/profiling` | Auth-wrapped |
| `GET,POST` | `/api/project/{project}/app/{app}/tracing` | Auth-wrapped |
| `GET,POST` | `/api/project/{project}/app/{app}/logs` | Auth-wrapped |
| `POST` | `/api/project/{project}/app/{app}/risks` | Auth-wrapped |
| `GET` | `/api/project/{project}/node/{node}` | Auth-wrapped |
| `*` | `/api/project/{project}/prom/api/v1/{rest:.+}` | Auth-wrapped Prometheus proxy |
| `GET` | `/.well-known/oauth-protected-resource` | OAuth/MCP metadata |
| `GET` | `/.well-known/oauth-authorization-server` | OAuth/MCP metadata |
| `POST` | `/oauth/register` | OAuth/MCP |
| `GET,POST` | `/oauth/authorize` | OAuth/MCP |
| `POST` | `/oauth/token` | OAuth/MCP |
| `POST` | `/oauth/revoke` | OAuth/MCP |
| `*` | `/mcp` | MCP handler |
| `*` | `/api/v1/query_range` | API-key auth |
| `*` | `/api/v1/series` | API-key auth |
| `*` | `/api/v1/metadata` | API-key auth |
| `*` | `/api/v1/label/{labelName}/values` | API-key auth |
| `GET` | `/api/clickhouse-config` | API-key auth |
| `CONNECT` | `/api/clickhouse-connect` | Manual API-key check then TCP tunnel to configured ClickHouse |
| `POST` | `/stats` | Unauthenticated stats event ingest |
| `GET` | `/stats` | Unauthenticated usage/infra stats response |
| `*` | `/static/` | Static assets |
| `POST` | `/sso/saml` | Enterprise SAML ACS, inferred |
| `GET` | `/sso/oidc` | Enterprise OIDC callback, inferred |
| `GET` | `/api/sso-login` | Enterprise SSO login, inferred |
| `GET` | `/api/sso-status` | Enterprise SSO status, inferred |

Frontend routes also appear in the bundled Vue assets, including `/login`, `/logout`, `/sso/saml`, `/auth/mcp-consent`, `/p/settings/:tab?`, `/p/:projectId/settings/:tab?`, `/p/:projectId/:view?/:id?/:report?`, `/`, and wildcard redirect. These are frontend routes, not necessarily backend API handlers.

## 6. Secrets and key material

Secret regex results:

- No real AWS access key/secret key found.
- No GitHub token found.
- No Slack token found.
- No Google API key found.
- No OpenAI/Anthropic API key found.
- No JWT token found.
- No URL basic-auth credential found.
- Some strings such as `api_key`, `client_secret`, `secret_access_key`, `auth_secret`, and `LICENSE_KEY` are field/config names, not secret values.

Embedded PEM findings:

| Type | Offset | Fingerprint | Assessment |
|---|---:|---|---|
| `CERTIFICATE` | `0x14a84c5` | `sha256:c260044af49b62f9` | Embedded public certificate or test fixture likely; verify source intent. |
| `RSA PRIVATE KEY` | `0x14f579b` | `sha256:3189df7e928dd0b2` | Sensitive-looking PEM block. Requires source/build verification. Do not expose publicly. |
| `RSA TESTING KEY` | `0x14fa9bb` | `sha256:8cee609888800efd` | Appears test/demo by label, but still should be verified. |

The private key value is intentionally not printed in this report.

## 7. Security findings

### Finding A: unauthenticated `/debug/pprof/`

Evidence:

- OSS v1.22.0 route setup registers `router.PathPrefix("/debug/pprof/").Handler(http.DefaultServeMux)`.
- This route is registered before app auth wrappers and is not wrapped with `a.Auth`.
- Binary includes matching debug/source/symbol material and route strings.

Impact if exposed publicly:

- Runtime profiling endpoints can leak goroutine, heap, command-line, and memory-derived information.
- CPU/heap profiling can be abused for reconnaissance and potential performance impact.

Recommendation:

- Remove pprof from production builds, bind it only to localhost/admin network, or protect it behind strong admin authentication.

### Finding B: unauthenticated `/stats` GET/POST

Evidence:

- `POST /stats` calls `statsCollector.RegisterRequest(r)` without `a.Auth`.
- `GET /stats` calls `statsCollector.Stats(r, w)` without `a.Auth`.
- `Stats()` returns `c.collect()`, which includes instance UUID/version/edition, DB type, integration flags, infrastructure counts, kernel versions, cloud/service summaries, API/MCP usage counters, users by role, and performance summaries.
- `collect()` resets some counters while collecting them.

Impact if exposed publicly:

- Information disclosure about deployment shape, integrations, users by role, API usage, and environment details.
- Unauthenticated GET can drain/reset usage counters.
- Unauthenticated POST can poison page-view/device-size/theme counters.

Recommendation:

- Require admin auth or an internal-only network boundary for `/stats`.
- Avoid resetting counters on unauthenticated GET-style reads.

### Finding C: default HTTP listener risk

Evidence:

- Default config uses `ListenAddress: ":8080"`.
- TLS is optional and requires explicit HTTPS/TLS configuration.

Impact:

- If deployed directly on a public interface without a reverse proxy/TLS, credentials/session material and API-key traffic may be exposed over plaintext HTTP.

Recommendation:

- Put the service behind TLS, set secure proxy headers carefully, and restrict direct HTTP listener exposure.

### Finding D: dependency vulnerabilities with vulnerable symbols present

`govulncheck -mode=binary -scan=symbol` reported 4 vulnerabilities that appear to have vulnerable symbols present in the binary:

| ID | Module | Found | Fixed | Summary |
|---|---|---:|---:|---|
| `GO-2026-4945` | `github.com/go-jose/go-jose/v4` | `v4.1.3` | `v4.1.4` | JWE decryption panic / denial of service. |
| `GO-2026-4762` | `google.golang.org/grpc` | `v1.67.1` | `v1.79.3` | gRPC-Go authorization bypass via missing leading slash in `:path`. |
| `GO-2026-4753` | `github.com/russellhaering/goxmldsig` | `v1.3.0` | `v1.6.0` | XML signature bypass via loop variable capture. |
| `GO-2025-3603` | `github.com/ClickHouse/ch-go` | `v0.62.0` | `v0.65.0` | Query smuggling in ClickHouse client library. |

Grype additionally reported 47 dependency vulnerability rows across the SBOM:

- 10 Critical
- 14 High
- 20 Medium
- 3 Low

Prioritize the 4 govulncheck symbol-level findings first because they are more likely to affect reachable code paths than module-only findings.

Reference URLs:

- https://pkg.go.dev/vuln/GO-2026-4945
- https://pkg.go.dev/vuln/GO-2026-4762
- https://pkg.go.dev/vuln/GO-2026-4753
- https://pkg.go.dev/vuln/GO-2025-3603

## 8. Malware/backdoor assessment

Static indicators checked:

| Indicator | Result | Notes |
|---|---:|---|
| Direct native `execve`/`system`/`popen` imports | 0 | No direct native process-spawn import found. |
| Go `os/exec` process-spawn symbols | 0 | No Go process-spawn symbol found. |
| Miner/C2 keywords after cleanup | 0 | No clean miner/C2 keyword hit. |
| Dynamic loader imports | 2 | `dlopen`, `dlsym`; expected with CGO/dynamic libraries, review runtime library paths. |
| Shell/download/persistence strings | present as string-only | Samples were mostly frontend bundles, docs, Material Design icon text, or library strings. No execution path proven. |

Conclusion:

- No static evidence of malware, persistence, downloader, cryptominer, or backdoor behavior was found.
- This is not equivalent to a runtime sandbox verdict. A full malware verdict would require executing the Linux ARM64 binary in an isolated lab and monitoring filesystem, process, network, and DNS behavior.

## 9. Notable module inventory

Selected modules from the SBOM:

- `github.com/coroot/enterprise v1.22.0`
- `github.com/coroot/coroot v1.22.0`
- `github.com/openai/openai-go/v3 v3.22.0`
- `github.com/anthropics/anthropic-sdk-go v1.22.1`
- `github.com/coreos/go-oidc/v3 v3.17.0`
- `github.com/crewjam/saml v0.4.14`
- `github.com/go-jose/go-jose/v4 v4.1.3`
- `github.com/golang-jwt/jwt/v4 v4.4.3`
- `github.com/golang-jwt/jwt/v5 v5.3.1`
- `google.golang.org/grpc v1.67.1`
- `github.com/ClickHouse/ch-go v0.62.0`
- `github.com/ClickHouse/clickhouse-go/v2 v2.8.3`
- `github.com/prometheus/prometheus v0.300.0`
- `github.com/russellhaering/goxmldsig v1.3.0`

Full module list: `/Users/itsmac/Desktop/auto-scan-vuln-lic/analysis/coroot-ee/full-inventory/syft-sbom.txt`

## 10. Limitations

- Analysis is static. The binary was not run because it is a Linux ARM64 executable and should be executed only in an isolated lab.
- Enterprise source code was not fully available. Route corroboration used Coroot OSS v1.22.0 plus enterprise symbols/strings from the binary.
- Secret scanning is regex/string/PEM-based. It can miss runtime-generated secrets or encrypted/encoded config blobs.
- Vulnerability scanners report dependency risk. Reachability beyond govulncheck symbol detection still needs application-level testing.
