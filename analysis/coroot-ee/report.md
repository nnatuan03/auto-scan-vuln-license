# Phan tich tinh binary `coroot-ee`

Ngay phan tich: 2026-06-12 (Asia/Ho_Chi_Minh)

Target: `/Users/itsmac/Documents/Binary/coroot-ee`

Pham vi: phan tich tinh binary, khong chay truc tiep binary Linux/arm64 tren macOS. Khong phan tich hoac huong dan bypass license.

## 1. Fingerprint

- Loai file: ELF 64-bit LSB executable, ARM aarch64, dynamically linked.
- Interpreter: `/lib/ld-linux-aarch64.so.1`.
- BuildID SHA1: `3c3b892fcaa374294cf2cdbefde27ebbfc5d5987`.
- SHA256: `8897486973706d2850f9ec8fbc8767d0dadce96983502ce7c047ebd35487813d`.
- Trang thai: co `.debug_info`, `.debug_line`, `.symtab`; khong stripped. Viec reverse engineering kha thuan loi.
- Entry point: `0x402c00`.
- Go build info:
  - Go: `go1.25.11`.
  - Module path: `github.com/coroot/enterprise`.
  - Main module: `(devel)`.
  - Version injected: `main.version=1.22.0`.
  - Target: `GOOS=linux`, `GOARCH=arm64`, `GOARM64=v8.0`.
  - `CGO_ENABLED=1`, `buildmode=exe`.

## 2. Thanh phan va chuc nang chinh

- Day la binary Coroot Enterprise, co phu thuoc `github.com/coroot/coroot v1.22.0`.
- Co server HTTP, gRPC/OTLP, UI Vue/static asset embed, SQLite/Postgres, ClickHouse, Prometheus query/remote write, alert/incident/RCA, RBAC, SSO OIDC/SAML, MCP/OAuth, AI RCA, Slack/Opsgenie/PagerDuty/Teams/Webhook integrations.
- Cac package noi bat trong symbol table:
  - `github.com/coroot/coroot/api`, `collector`, `model`, `db`, `config`, `rbac`, `grpc`.
  - `github.com/coroot/enterprise/api`, `enterprise/db`, `enterprise/rca`, `enterprise/licenses`.
- License manager co mat: `licenses.NewManager`, `CheckLicense`, `validate`, `calcUsage`, flag/env `license-key` / `LICENSE_KEY`.

## 3. Be mat tan cong quan sat duoc

- HTTP routes tu source OSS v1.22.0 doi chieu voi symbol/debug info:
  - `/api/login`, `/api/logout`, `/api/user`, `/api/users`, `/api/roles`, `/api/sso`, `/api/ai`, `/api/project/...`.
  - Collector: `/v1/metrics`, `/v1/traces`, `/v1/logs`, `/v1/profiles`, `/v1/config` dung `X-API-Key`.
  - Prometheus-compatible API dung API key: `/api/v1/query_range`, `/api/v1/series`, `/api/v1/metadata`, `/api/v1/label/{labelName}/values`.
  - MCP/OAuth: `/.well-known/oauth-*`, `/oauth/register`, `/oauth/authorize`, `/oauth/token`, `/oauth/revoke`, `/mcp`.
  - Debug: `/debug/pprof/`.
- gRPC server mac dinh duoc cau hinh trong OSS la `:4317` neu khong disable, dang ky OTLP logs/traces va lay project qua metadata `X-API-Key`.
- Auth:
  - Cookie `coroot_session` ky HMAC-SHA256 bang `auth_secret`.
  - Password dung bcrypt.
  - MCP token dung JWT v5 HS256, co `WithValidMethods(HS256)` va `WithAudience(...)`.

## 4. Ket qua bao mat uu tien

| Muc | Phat hien | Chung cu | Khuyen nghi |
| --- | --- | --- | --- |
| Critical | `google.golang.org/grpc v1.67.1` bi OSV gan `GHSA-p77j-4mvh-x3m3` / `CVE-2026-33186`, auth bypass lien quan `:path`. | Binary co gRPC server, OTLP service, config `GRPC_LISTEN`; OSV fixed `1.79.3`. | Nang cap/rebuild it nhat `grpc-go >= 1.79.3`; han che network den `:4317`; dat proxy/WAF chi chap nhan path hop le. |
| High | `github.com/russellhaering/goxmldsig v1.3.0` bi `GHSA-479m-364c-43vc` / `CVE-2026-33487`, signature bypass. | Binary co SAML (`SamlACS`) va `crewjam/saml`; OSV fixed `1.6.0`. | Nang `goxmldsig >= 1.6.0`; kiem thu SAML signature wrapping/bypass voi IdP test. |
| High | `github.com/golang-jwt/jwt/v4 v4.4.3` bi `GHSA-mh63-6h87-95cp` / `CVE-2025-30204`, DoS qua header parsing. | jwt/v4 co trong dependency; MCP dung jwt/v5 nen can xac minh jwt/v4 duoc route nao goi. | Nang `jwt/v4 >= 4.5.2`; neu khong dung thi loai bo transitive dependency. |
| High | `github.com/go-jose/go-jose/v4 v4.1.3` bi `GHSA-78h2-9frx-2jm8`, panic trong JWE decrypt. | Co OIDC/JOSE deps; reachability tuy thuoc cau hinh OIDC/JWE. | Nang `go-jose/v4 >= 4.1.4`; test token/JWE loi. |
| High | `github.com/prometheus/prometheus v0.300.0` co nhieu advisory OSV high/moderate. | Binary embed Prometheus parser/prompb va remote-write/Prom API. | Nang theo Coroot upstream; xac minh endpoint nao thuc su expose chuc nang bi anh huong. |
| Medium | gRPC `MaxRecvMsgSize(math.MaxInt)`. | OSS `grpc/server.go` doi chieu symbol `NewServer.MaxRecvMsgSize`. | Dat limit hop ly o app/proxy; khong expose gRPC ra internet. |
| Medium | `/debug/pprof/` duoc route truc tiep. | `main.go` OSS va symbol `net/http/pprof.*`. | Chi bind private interface, chan qua ingress, hoac tat trong production. |
| Medium | Session cookie thieu `Secure` va `SameSite`; payload chi co user id va HMAC, khong co exp server-side trong signed value. | `SetSessionCookie` OSS auth.go. | Bat HTTPS-only, them `Secure`, `SameSite`, va expiry/rotation server-side. |
| Medium | Tinh nang webhook/Prometheus remote write co the tao outbound request den URL cau hinh; co tuy chon TLS skip verify. | `notifications/webhook.go`, `collector/metrics.go`, flags `*_TLS_SKIP_VERIFY`, string `DISABLE_WEBHOOK_URL_VALIDATION`. | Coi day la SSRF boundary quan tri: egress allowlist, metadata IP block, audit nguoi co quyen sua integration. |
| Info | Co block RSA private key trong rodata tai offset `0x14f579b`. | `strings` thay PEM block; chua tim duoc exact source trong module cache/OSS clone. | Xac minh bang source build/vendored deps. Khong thay match voi AWS/GitHub/Slack/Google/JWT/OpenAI key thuc; OpenAI hits la false positive tu icon/CSS. |

## 5. Dependency OSV dang chu y

- Tong so dependency Go: 108.
- OSV deduped: 38 advisory/alias rows.
- Link OSV quan trong:
  - `https://osv.dev/vulnerability/GHSA-p77j-4mvh-x3m3`
  - `https://osv.dev/vulnerability/GHSA-479m-364c-43vc`
  - `https://osv.dev/vulnerability/GHSA-mh63-6h87-95cp`
  - `https://osv.dev/vulnerability/GHSA-78h2-9frx-2jm8`
  - `https://osv.dev/vulnerability/GHSA-6g7g-w4f8-9c9x`
  - `https://osv.dev/vulnerability/GHSA-8rm2-7qqf-34qm`
  - `https://osv.dev/vulnerability/GHSA-wg65-39gg-5wfj`

Luu y: OSV xac nhan dependency/version bi anh huong, nhung exploitability phu thuoc route nao goi den code do va cau hinh runtime.

## 6. Khong thay dau hieu sau trong phan tich tinh

- Khong thay import/symbol app-level `os/exec` hay `syscall.Exec`.
- Khong thay hardcoded AWS access key, GitHub PAT, Slack token, Google API key, JWT mau hop le, OpenAI API key thuc.
- Khong thay dau hieu dropper/persistence ro rang trong symbol/string.

## 7. Artefacts da tao

- `file-header.txt`: thong tin ELF/header.
- `sections.txt`: section table.
- `buildinfo.txt`, `build-summary.txt`, `build-settings.tsv`, `deps.tsv`: Go build info va dependency.
- `symbols.txt`: 65,848 symbols.
- `strings-n6.txt`: strings extracted.
- `urls.txt`, `paths.txt`: URL/path candidates.
- `main-main.disasm.txt`: disassembly `main.main`.
- `osv-query.json`, `osv-results.json`, `osv-details.json`, `osv-deduped.tsv`: ket qua OSV.
- `coroot-src/`: clone OSS Coroot tag v1.22.0 dung de doi chieu nhung phan open-source.
