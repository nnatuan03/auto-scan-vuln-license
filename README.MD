# Auto Scan Vulnerability & License

> Công cụ dòng lệnh tự động phát hiện loại mã nguồn, sinh SBOM, quét lỗ hổng phụ thuộc và giấy phép bằng **Trivy**, sau đó xuất báo cáo HTML tổng hợp kèm xuất Excel.

**Mục tiêu:** chỉ cần chạy một lệnh trên thư mục mã nguồn — công cụ tự xử lý phần còn lại, từ detect, sinh SBOM, scan, normalize license, tới báo cáo cuối cùng.

---

## Mục lục

1. [Bắt đầu nhanh](#bắt-đầu-nhanh)
2. [Giao diện dòng lệnh](#giao-diện-dòng-lệnh)
3. [Dashboard tiến độ](#dashboard-tiến-độ)
4. [Yêu cầu cài đặt](#yêu-cầu-cài-đặt)
5. [Các loại mã nguồn được hỗ trợ](#các-loại-mã-nguồn-được-hỗ-trợ)
6. [Luồng quét](#luồng-quét)
7. [Đối chiếu tài liệu ITS](#đối-chiếu-tài-liệu-its)
8. [Cấu trúc mã nguồn](#cấu-trúc-mã-nguồn)
9. [Đầu ra](#đầu-ra)
10. [Sử dụng báo cáo](#sử-dụng-báo-cáo)
11. [Gỡ lỗi khi kết quả thiếu/sai](#gỡ-lỗi-khi-kết-quả-thiếusai)
12. [Ma trận kiểm thử đa ecosystem](#ma-trận-kiểm-thử-đa-ecosystem)
13. [Tùy chọn CLI](#tùy-chọn-cli)
14. [Lưu ý bảo mật & an toàn mã nguồn](#lưu-ý-bảo-mật--an-toàn-mã-nguồn)
15. [Lỗi thường gặp](#lỗi-thường-gặp)

---

## Bắt đầu nhanh

### Windows / PowerShell

```powershell
.\run_scan.ps1 -Path "D:\Projects"
```

### Mọi hệ điều hành — chạy trực tiếp bằng Python

```bash
python autoscan.py "D:/Projects"
```

### Ý nghĩa tham số `Path`

- Nếu `Path` trỏ tới **một project** (có `pom.xml`, `package.json`, `pubspec.yaml`, …) — công cụ quét một project.
- Nếu `Path` trỏ tới **một file đơn lẻ** (`requirements.txt`, lockfile, IaC file, …) — công cụ quét file đó bằng Trivy filesystem target.
- Nếu `Path` trỏ tới **thư mục cha** chứa nhiều service ở cấp 1 — công cụ tự phát hiện từng service, quét song song rồi gộp báo cáo.
- Những thư mục cấp 1 **không có marker** nhận dạng vẫn được quét bằng `trivy fs` với `kind = unknown` để tránh bỏ sót.

Sau khi chạy xong, mở báo cáo tổng hợp:

```text
D:\Projects\scan-results\consolidated-report.html
```

---

## Giao diện dòng lệnh

Trong quá trình quét, terminal sẽ in log realtime cho **mỗi lệnh ngoài** được gọi (Maven, Gradle, npm/npx, Flutter, Trivy, …), mỗi nhóm lệnh có màu riêng:

```text
[RUN] trivy sbom --scanners vuln,license --format json ...
[OK ] exit=0 time=1.24s trivy sbom --scanners vuln,license --format json ...
[RUN] trivy fs --scanners vuln,license,secret,misconfig --license-full --format json ...
[OK ] exit=0 time=2.40s trivy fs --scanners vuln,license,secret,misconfig --license-full --format json ...
[FAIL] exit=1 time=0.42s gradle cyclonedxBom
```

Khi quét theo lô, một **dashboard tiến độ** sẽ xuất hiện và cập nhật liên tục (xem mục kế tiếp).

Sau khi hoàn tất, terminal in **tóm tắt**:

```text
Auto Scan Summary
=================
Root       : D:\Projects
Run output : D:\Projects\scan-results\20260609-153000
Projects   : 10
OK         : 8
FAIL       : 2
Report     : D:\Projects\scan-results\20260609-153000\consolidated-report.html
Stable copy: D:\Projects\scan-results\consolidated-report.html
Debug      : D:\Projects\scan-results\20260609-153000\debug-report.md
Stable dbg : D:\Projects\scan-results\debug-report.md

[OK ] backend-api [maven]  vulns=4  licenses=87  sbom=ok
[OK ] web-portal  [node]   vulns=2  licenses=43  sbom=ok
[FAIL] legacy-app [gradle] vulns=0  licenses=0   sbom=fail
       error: gradle cyclonedxBom exited with code 1
```

---

## Dashboard tiến độ

Dashboard tự động cập nhật mỗi khi một service hoàn tất hoặc khi bắt đầu gộp báo cáo:

```text
Auto Scan Dashboard
===================
Stage    : scanning
Progress : [###############---------------] 5/10 ( 50.0%)
Status   : DONE=5 OK=5 FAIL=0 RUNNING=5
Elapsed  : 03:20
ETA      : 03:20
```

- **Stage** — giai đoạn hiện tại: `scanning` hoặc `merging`.
- **Progress** — thanh tiến độ dạng text + phần trăm.
- **Status** — số service `DONE` / `OK` / `FAIL` / `RUNNING`.
- **Elapsed / ETA** — thời gian đã chạy và thời gian ước tính còn lại.

Có thể tắt dashboard bằng `--no-dashboard` (CLI) hoặc `-NoDashboard` (PowerShell) khi cần log gọn cho CI.

---

## Yêu cầu cài đặt

### Bắt buộc

| Thành phần | Phiên bản tối thiểu | Ghi chú |
| --- | --- | --- |
| **Python** | **3.10+** | Công cụ dùng cú pháp `PEP 604` (`list[str] \| None`, `X \| Y`). |
| **Trivy** | mới nhất | Phải có sẵn trong `PATH`, hoặc dùng `--install-missing` để công cụ tự cài nếu có `brew` / `winget` / `apt-get`. |
| **PowerShell** | 5.1+ (Windows) | Chỉ cần khi dùng wrapper `run_scan.ps1`. |

### Khuyến nghị — để SBOM chính xác hơn theo từng hệ sinh thái

| Ecosystem | Công cụ ưu tiên | Fallback |
| --- | --- | --- |
| **Maven** | `mvnw` / `mvnw.cmd` trong project | `mvn` trong `PATH` |
| **Gradle** | `gradlew` trong project | `gradle` trong `PATH` |
| **Node.js** | `node`, `npm`, `npx` | — |
| **.NET** | `dotnet` | Tự cài `dotnet-CycloneDX` nếu thiếu |
| **Flutter** | `flutter` | — |

### Kiểm tra nhanh

```powershell
python --version
trivy --version
```

### Cài đặt môi trường Python

Công cụ **chỉ dùng thư viện chuẩn** của Python, nên không cần `pip install` gì thêm. Tuy nhiên, để có một môi trường nhất quán và có thể tái lập, hãy dùng file `requirements.txt` đi kèm repo (chỉ chứa comment hướng dẫn — coi như "anchor" cho `pip install -r requirements.txt`).

```bash
python -m venv .venv
# Windows
.venv\Scripts\activate
# macOS / Linux
source .venv/bin/activate

pip install -r requirements.txt
```

---

## Các loại mã nguồn được hỗ trợ

| Hệ sinh thái | Marker nhận dạng |
| --- | --- |
| **Maven** | `pom.xml` |
| **Gradle** | `build.gradle`, `build.gradle.kts`, `settings.gradle`, `settings.gradle.kts`, `gradlew`, `gradlew.bat` |
| **Node.js** | `package.json`, `package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock`, `pnpm-lock.yaml`, `bun.lock`, `bun.lockb` |
| **Flutter** | `pubspec.yaml` |
| **.NET** | `.sln`, `.csproj` |
| **Python** | `requirements.txt`, `requirements.lock`, `pyproject.toml`, `Pipfile`, `Pipfile.lock`, `poetry.lock`, `uv.lock`, `conda-lock.yml` |
| **Go** | `go.mod`, `go.sum` |
| **Rust** | `Cargo.toml`, `Cargo.lock` |
| **PHP** | `composer.json`, `composer.lock` |
| **Ruby** | `Gemfile`, `Gemfile.lock` |
| **Swift** | `Package.swift`, `Package.resolved` |
| **CocoaPods** | `Podfile`, `Podfile.lock` |
| **Elixir / Erlang** | `mix.exs`, `mix.lock`, `rebar.config`, `rebar.lock` |
| **Java archives / SBT** | `*.jar`, `*.war`, `*.ear`, `*.par`, `sbt.lock` |
| **Conda / Julia / R / C/C++** | `environment.yml`, `conda-lock.yml`, `Project.toml`, `Manifest.toml`, `renv.lock`, `pak.lock`, `conan.lock`, `vcpkg.json` |
| **IaC / config** | `Dockerfile`, `Containerfile`, `docker-compose.yml`, `Chart.yaml`, `Chart.lock`, `kustomization.yaml`, `main.tf`, `.terraform.lock.hcl`, `serverless.yml` |
| **Single file** | File được truyền trực tiếp qua CLI — quét bằng `trivy fs <file>` |
| **Unknown** | Thư mục cấp 1 không có marker — fallback `trivy fs` |

Nếu không có generator riêng hoặc generator bị lỗi, công cụ **luôn fallback** về:

```bash
trivy fs --format cyclonedx
```

---

## Luồng quét

Với **mỗi** project / service:

1. **Phát hiện loại mã nguồn** dựa trên marker.
2. **Luôn sinh SBOM mới** cho lần quét hiện tại — *không tái sử dụng* SBOM có sẵn trong mã nguồn để tránh kết quả cũ khi quét lại.
3. **Chuẩn bị dependency metadata nếu được bật**:
   - `--prepare-deps`: hỏi trước khi chạy lệnh chuẩn bị metadata thiếu.
   - `--prepare-deps-auto`: tự chạy trong môi trường đã tin cậy / sandbox.
   - Hiện hỗ trợ Flutter: nếu có `pubspec.yaml` nhưng thiếu `pubspec.lock`, chạy `flutter pub get` trước khi scan.
4. **Prebuild Maven lib nội bộ** (nếu thư mục quét có nhiều Maven project tham chiếu lẫn nhau):
   - Đọc tất cả `pom.xml`, tìm các Maven project được tham chiếu bởi project khác trong cùng thư mục nguồn.
   - Chạy `mvn clean install -DskipTests -Dmaven.test.skip=true -DskipITs` cho các lib / parent nội bộ trước khi quét.
   - Mục tiêu: đảm bảo local `.m2` có đủ cả `.jar` lẫn `.pom`, tránh trường hợp service quét ra dependency version cũ vì thiếu metadata lib nội bộ.
   - Có thể bỏ qua bước này để debug nhanh: `--skip-maven-prebuild` (CLI) hoặc `-SkipMavenPrebuild` (PowerShell).
5. **Sinh SBOM theo ecosystem** nếu có công cụ phù hợp:

   | Ecosystem | Lệnh ưu tiên | Ghi chú |
   | --- | --- | --- |
   | Maven | `mvnw.cmd` / `mvnw` nếu có, fallback `mvn org.cyclonedx:cyclonedx-maven-plugin:makeAggregateBom -DskipTests` | |
   | Gradle | `gradlew cyclonedxBom` hoặc `gradle cyclonedxBom` | Nếu thiếu plugin, dùng init script tạm apply `org.cyclonedx.bom` v2.3.1 — **không sửa** `build.gradle.kts`. |
   | Node.js (npm lock) | `npx --yes @cyclonedx/cyclonedx-npm --ignore-npm-errors --package-lock-only` | |
   | Node.js (yarn / pnpm / bun) | fallback `trivy fs` | |
   | .NET | `dotnet-CycloneDX <project> -j` | Nếu thiếu tool mà có `dotnet`, tự chạy `dotnet tool install --global CycloneDX`. |
   | Flutter | fallback `trivy fs`, sau đó enrich license từ `pubspec.lock` / pub.dev trước normalize | Chỉ bổ sung license cho package đang thiếu, không ghi đè license đã có. |
   | Python / Go / PHP / Ruby / unknown | fallback `trivy fs` | |

   Nếu generator riêng fail hoặc không sinh ra SBOM mới → fallback `trivy fs --format cyclonedx`.
6. **Reconcile phiên bản** trong SBOM với phiên bản mới nhất tìm được trong mã nguồn / lock file hiện có. Ví dụ: Node có cả `package-lock.json` và `yarn.lock`, nếu SBOM ra `1.80.0` nhưng `package.json` / `yarn.lock` đang ở `1.84.0` — công cụ sẽ cập nhật SBOM lên `1.84.0` trước khi scan. Công cụ **không tự truy vấn registry** để nâng cấp dependency ngoài mã nguồn.
7. **Enrich license Flutter** nếu service có `pubspec.lock`: đọc package/version hosted từ lock file, tra cứu best-effort trên pub.dev, ghi `pub-license-enrich.log` và cache `pub-license-cache.json`; package không đủ bằng chứng vẫn giữ `LicenseRef-No-Declared-License`.
8. **Chuẩn hóa license** thành `SBOM.cdx-fix.json`.
9. **Chạy full source scan** cho mỗi service / file:
   - `trivy fs --scanners vuln,license,secret,misconfig --license-full --format json` → `filesystem-report.json`.
   - Đây là bước bắt buộc để không bỏ sót secret, misconfiguration/IaC và các ecosystem mà SBOM generator riêng không bao phủ đủ.
   - Nếu bước này fail, service bị đánh dấu `FAIL` thay vì báo OK giả.
10. **Chạy Trivy trên SBOM đã chuẩn hóa** cho dependency/license report tương thích báo cáo cũ:
   - `trivy sbom --scanners vuln,license --format json` → `report.json`.
   - Từ `report.json` tách ra `license.json`, `license.txt`, `vuln.json`.
11. **Đối chiếu license** trong `SBOM.cdx-fix.json` với `report.json` / `license.json`; nếu Trivy trả thiếu license của package, công cụ tự bổ sung từ SBOM. Component không khai báo license sẽ hiện `LicenseRef-No-Declared-License` để không bị "mất im lặng". Một số package phổ biến có metadata thiếu/không chuẩn được xử lý qua policy nội bộ (`license_policy.py`) như Flutter SDK (`BSD-3-Clause`), Swagger parser (`Apache-2.0`), QueryDSL (`Apache-2.0`), `xtend` (`MIT`), Java EE CDDL/GPLv2 CE, Oracle JDBC (`LicenseRef-Oracle-FUTC`). File manifest như `pom.xml`, `pubspec.lock` không được đưa vào license package report.
12. **Sinh báo cáo HTML** cho từng service:
   - `report.html`
   - `report-vuln.html`

### Lưu ý về độ đầy đủ

- Trivy có thể cần lockfile, cache, vendor directory hoặc package manager metadata để xác định đủ dependency/license cho một số ecosystem.
- Công cụ luôn chạy full filesystem scan và license full mode. Các lệnh có thể tạo metadata từ source lạ chỉ chạy khi bật `--prepare-deps` / `--prepare-deps-auto`.
- Nếu source bị thiếu file sinh ra từ dependency resolution (`node_modules`, cache package manager, `project.assets.json`, lockfile, vendor metadata, …), hãy pull/restore artifact hoặc bật prepare-deps trong môi trường sandbox trước khi scan lại.
13. **Merge tất cả service** thành `consolidated-report.html`.
14. **Sinh debug report** `debug-report.md` / `debug-report.json` để đối chiếu với tài liệu và debug từng service.

---

## Đối chiếu tài liệu ITS

Công cụ đang cover các case license / dependency scan trong tài liệu, trừ các phần đã được loại khỏi scope:

| Case trong tài liệu | Cách công cụ cover |
| --- | --- |
| Trivy dependency vulnerability scan | Chạy `trivy sbom --scanners vuln --format json`, sau đó sinh `report-vuln.html`. |
| Gradle license scan | Chạy `gradlew / gradle cyclonedxBom`; nếu thiếu plugin, dùng init script tạm với `org.cyclonedx.bom` v2.3.1. |
| Maven license scan | Prebuild / install lib Maven nội bộ trong thư mục nguồn nếu service khác phụ thuộc, sau đó chạy `mvnw / mvn org.cyclonedx:cyclonedx-maven-plugin:makeAggregateBom`. |
| Node.js npm / package-lock license scan | Chạy `npx --yes @cyclonedx/cyclonedx-npm --ignore-npm-errors`; nếu có lock npm thì dùng `--package-lock-only`. |
| .NET license scan | Tự cài `CycloneDX` nếu thiếu, rồi chạy `dotnet-CycloneDX` trên `.sln` / `.csproj`. |
| Flutter license enrichment | Tự động đọc `pubspec.lock`, lấy license từ pub.dev cho package hosted còn thiếu license trong SBOM, có cache/log để audit. |
| Normalize SBOM trước khi scan license | Tạo `SBOM.cdx-fix.json` bằng module normalize nội bộ. |
| License TXT / JSON | Tạo `license.txt` và `license.json` cho từng service. |

### Khác biệt có chủ đích

- SBOM được sinh mới trong `scan-results\<timestamp>` mỗi lần quét, **không ghi / dependency vào `third-party`** để tránh re-scan dùng SBOM cũ.
- Gradle **không tự sửa** `build.gradle` / `build.gradle.kts`; init script tạm chỉ nằm trong thư mục output.
- `report-vuln.html` được sinh từ `vuln.json` bằng **template nội bộ** thay vì `html.tpl` của Trivy.
- SonarQube và script CI/CD / Jenkins / email đang được loại theo scope đã chốt.

---

## Cấu trúc mã nguồn

```text
auto-scan-vuln-lic/
├── autoscan.py                 # Entrypoint chính, nhận path và điều phối quét
├── run_scan.ps1                # Wrapper PowerShell trên Windows
├── README.MD                   # File này
├── requirements.txt            # Cài đặt môi trường Python (xem chi tiết)
│
├── autoscan/
│   ├── __init__.py
│   ├── batch.py                # Quét nhiều project / service song song và gộp báo cáo
│   ├── config.py               # Hằng số cấu hình, marker hệ sinh thái, ignore-dir
│   ├── debug_report.py         # Sinh debug report đối chiếu tài liệu, marker, command, count SBOM / license
│   ├── dependency_health.py    # Phát hiện lock file thiếu / cũ và mismatch manifest ↔ lock trước khi sinh SBOM
│   ├── dependency_preparer.py  # Chuẩn bị dependency metadata thiếu khi bật `--prepare-deps` / `--prepare-deps-auto`
│   ├── detector.py             # Tự phát hiện Maven, Gradle, Node, Flutter, .NET, Python, Go, Rust, IaC, ...
│   ├── flutter_license_enricher.py # Bổ sung license Flutter từ `pubspec.lock` / pub.dev trước normalize
│   ├── license_inventory.py    # Bù license từ SBOM vào report nếu Trivy không trả đủ dòng license
│   ├── license_normalizer.py   # Chuẩn hóa license SBOM về SPDX / LicenseRef
│   ├── license_policy.py       # Policy override/classify license thiếu metadata hoặc LicenseRef nội bộ
│   ├── license_rules.py        # Bộ rule normalize license từ tên vendor / free-text về SPDX ID
│   ├── maven_prebuild.py       # Prebuild / install lib Maven nội bộ trước khi quét
│   ├── models.py               # Dataclass: Project, CommandRecord, ScanResult
│   ├── package_names.py        # Khôi phục package name bị thiếu từ PURL, PkgID, node_modules path, license file path, Target
│   ├── progress.py             # Dashboard terminal: tiến độ %, elapsed, ETA
│   ├── sbom_generator.py       # Sinh SBOM theo từng loại mã nguồn, fallback `trivy fs`
│   ├── scanner.py              # Quét một project / service
│   ├── terminal.py             # In command, status, màu terminal / PowerShell
│   ├── trivy_runner.py         # Chạy Trivy và sinh output JSON / TXT
│   ├── tool_installer.py       # Hỏi / tự cài tool scan thiếu (`trivy`, `flutter`, `maven`, ...)
│   ├── utils.py                # Tiện ích chung: subprocess, JSON, ensure_dir, copy_file
│   ├── version_reconciler.py   # Đối chiếu version SBOM với lock file / manifest hiện tại
│   └── reporting/
│       ├── __init__.py
│       ├── merge_report.py     # Engine sinh report HTML tổng hợp
│       ├── reports.py          # Facade gọi generator single / merged
│       └── single_report.py    # Engine sinh report HTML cho từng service
│
└── tests/
    ├── ecosystem_matrix.py     # Tạo fixture nhiều ecosystem để test detect / dependency-health / report recovery
    ├── test_dependency_preparer.py
    ├── test_tool_installer.py
    └── test_trivy_full_scan.py
```

---

## Đầu ra

### Ví dụ khi chạy

```bash
python autoscan.py "D:/Projects"
```

### Cấu trúc thư mục kết quả

```text
D:\Projects\scan-results\
├── consolidated-report.html      # Bản ổn định (ghi đè) trỏ tới lần chạy mới nhất
├── scan-summary.json              # Bản ổn định
├── debug-report.md                # Bản ổn định
├── debug-report.json              # Bản ổn định
│
└── 20260609-153000\               # Thư mục theo timestamp mỗi lần chạy
    ├── consolidated-report.html
    ├── scan-summary.json
    ├── debug-report.md
    ├── debug-report.json
    └── services\
        ├── backend-api\
        │   ├── SBOM.cdx.json
        │   ├── SBOM.cdx-fix.json
        │   ├── license-normalize.log
        │   ├── report.json
        │   ├── report.html
        │   ├── report-vuln.html
        │   ├── license.json
        │   ├── license.txt
        │   ├── vuln.json
        │   └── scan.log
        └── web-portal\
            └── ...
```

### Các file quan trọng

| File | Vai trò |
| --- | --- |
| `consolidated-report.html` | Báo cáo tổng hợp cuối cùng — mở file này để xem toàn bộ. |
| `scan-summary.json` | Tóm tắt máy-đọc-được: OK / FAIL, đếm vuln / license, path output từng service. |
| `debug-report.md` | Debug report dạng Markdown: đối chiếu tài liệu, service phát hiện, command đã chạy, count SBOM / license. |
| `debug-report.json` | Debug report dạng JSON — gửi / parse lại khi cần trace sau. |
| `services\<service>\scan.log` | Log command chi tiết để debug. |
| `services\<service>\license-normalize.log` | Thống kê số component có license trong SBOM và các license đã normalize. |

---

## Sử dụng báo cáo

Mở file:

```text
scan-results\consolidated-report.html
```

Báo cáo gồm:

- **Tổng quan** vulnerability / license.
- **Bảng vulnerability** — lọc theo package, severity, category, action.
- **Bảng license** — lọc tương tự, không có cột category / action.
- **Xuất Excel** — nút **Export Excel** ngay trong báo cáo.

### Xuất Excel

Trong báo cáo HTML có sẵn nút **Export**. File Excel sẽ được tải về máy của bạn. Đặc điểm:

- Cột `Severity` được tô màu:
  - `CRITICAL` — đỏ đậm
  - `HIGH` — đỏ
  - `MEDIUM` — vàng
  - `LOW` — xanh lá
- Mỗi package có nhiều dòng (ví dụ: nhiều CVE) thì các dòng đó được **merge** lên đầu để dễ đọc.
- Sheet `License` **bỏ** cột `Category` và `Action`.

> **Lưu ý:** nút Export Excel tải thư viện `xlsx-js-style@1.2.0` từ CDN (`cdn.jsdelivr.net`). Trình duyệt cần truy cập Internet, hoặc bạn cần cache CDN sẵn trong môi trường nội bộ.

---

## Gỡ lỗi khi kết quả thiếu/sai

### Bước 1 — Dry-run trước

Chạy dry-run để xem công cụ phát hiện được bao nhiêu service:

```bash
python autoscan.py "D:/Projects" --dry-run
```

### Bước 2 — Mở debug report

```text
D:\Projects\scan-results\debug-report.md
```

Kiểm tra theo thứ tự:

| Mục trong debug | Cần xem gì |
| --- | --- |
| `Document Coverage` | Case nào đang covered, case nào khác tài liệu có chủ đích, case nào bị loại. |
| `Services` | Service nào được phát hiện, kind gì, marker nào, SBOM sinh bằng generator nào. |
| `Maven Prebuild` | Lib / parent Maven nội bộ nào đã được `mvn clean install` trước khi quét, command nào fail. |
| `Dependency health` | Cảnh báo lock file thiếu, dependency trong manifest không có trong lock, hoặc manifest version cao hơn lock version. |
| `Commands` | Command thực tế đã chạy và exit code. |
| `Retry / fallback note` & `Command failures` | Command fail / success tiếp theo, kèm stderr tail — dùng để xem lý do fallback. |
| `Pkg name recovery` | Số dòng report gốc thiếu package name, số dòng công cụ khôi phục được, số dòng vẫn unknown. |
| `Version updates` | Số component trong SBOM được nâng lên version mới hơn tìm thấy trong mã nguồn / lock file. |
| `Fixed components` | Số component trong `SBOM.cdx-fix.json`; nếu con số đã thiếu thì lỗi nằm ở bước sinh SBOM. |
| `SBOM license rows` & `Trivy licenses` | Nếu SBOM có đủ license rows mà Trivy thiếu, công cụ sẽ backfill vào report. |

### Trạng thái dependency health hay gặp

| Status | Ý nghĩa |
| --- | --- |
| `DEPENDENCY_HEALTH_OK` | Không thấy mismatch manifest / lock trong các case công cụ hỗ trợ. |
| `LOCK_FILE_MISSING` | Có manifest (`package.json`, `pubspec.yaml`, `composer.json`, `Gemfile`, …) nhưng thiếu lock file tương ứng. |
| `MANIFEST_LOCK_MISMATCH` | Manifest yêu cầu version mới hơn nhưng lock vẫn resolve version cũ — quét sẽ theo lock / SBOM. |
| `LOCK_DEPENDENCY_MISSING` | Manifest khai báo dependency nhưng lock không có dependency đó. |
| `UNPINNED_DEPENDENCY` | Python `requirements.txt` có dependency không pin bằng `==`. |
| `BUILD_FILE_MISSING` | Không tìm thấy build / dependency manifest đủ để resolve dependency theo ecosystem. |

---

## Ma trận kiểm thử đa ecosystem

Chạy test fixture local, **không cần cài** Maven / Gradle / Flutter / PHP / Go:

```bash
python tests/ecosystem_matrix.py
```

Test tự sinh mã nguồn mẫu cho **Maven, Gradle, Node, Flutter, .NET, Python, Go, PHP, Ruby** và cả `unknown source`. Bộ `pytest` bổ sung kiểm tra full Trivy scan, marker mở rộng, cài tool thiếu và prepare-deps. Các case chính:

- Lock file OK.
- Lock file thiếu.
- Manifest khai báo version mới hơn lock.
- Dependency có trong manifest nhưng thiếu trong lock.
- Python dependency không pin version.
- Report recover package name bị thiếu.

---

## Tùy chọn CLI

### Một số ví dụ thường dùng

```bash
# Tăng số worker quét song song
python autoscan.py "D:/Projects" --max-workers 6

# Tăng độ sâu tìm project lồng nhau (hữu ích cho monorepo, frontend nằm trong apps/ packages/ frontend/)
python autoscan.py "D:/Projects" --recursive-depth 4

# Bỏ qua generator riêng, chỉ dùng trivy fs
python autoscan.py "D:/Projects" --trivy-only

# Quét một file đơn lẻ
python autoscan.py "D:/Projects/app/requirements.txt"

# Chỉ detect, không chạy Trivy / tool ngoài
python autoscan.py "D:/Projects" --dry-run

# Tắt dashboard tiến độ (log gọn cho CI)
python autoscan.py "D:/Projects" --no-dashboard

# Không in từng command ra terminal, tắt màu
python autoscan.py "D:/Projects" --hide-commands --no-color

# Đổi folder output
python autoscan.py "D:/Projects" --output "D:/Audit/scan-results"

# Tự cài tool scan còn thiếu bằng package manager hỗ trợ rồi scan
python autoscan.py "D:/Projects" --install-missing

# Không hỏi cài tool thiếu, chỉ báo lỗi/cảnh báo
python autoscan.py "D:/Projects" --no-install-prompt

# Hỏi trước khi chạy lệnh chuẩn bị dependency metadata bị thiếu
python autoscan.py "D:/Projects" --prepare-deps

# Tự chạy lệnh chuẩn bị dependency metadata bị thiếu
python autoscan.py "D:/Projects" --prepare-deps-auto
```

### Bảng tùy chọn

| Option | Mô tả |
| --- | --- |
| `--max-workers` | Số project quét song song. Mặc định `4`. |
| `--recursive-depth` | Độ sâu tìm project con / lồng nhau. Mặc định `5`. |
| `--trivy-only` | Bỏ qua generator Maven / Gradle / Node / .NET, chỉ dùng `trivy fs`. |
| `--skip-maven-prebuild` | Bỏ qua bước `mvn clean install` các Maven lib nội bộ trước khi quét. Chỉ nên dùng khi debug nhanh. |
| `--dry-run` | Chỉ detect project, không chạy Trivy hay tool ngoài. |
| `--output` | Đổi folder output mặc định (`<path>/scan-results`). |
| `--no-dashboard` | Tắt dashboard tiến độ trong terminal. |
| `--hide-commands` | Không in từng command ra terminal. |
| `--no-color` | Tắt màu terminal. |
| `--install-missing` | Tự cài tool scan còn thiếu nếu có package manager hỗ trợ (`brew`, `winget`, `apt-get`), sau đó scan lại. |
| `--no-install-prompt` | Không hỏi cài tool thiếu; ghi cảnh báo/lỗi để người dùng tự cài. |
| `--prepare-deps` | Hỏi trước khi chạy lệnh chuẩn bị dependency metadata còn thiếu trước scan. Hiện hỗ trợ Flutter `pubspec.lock` bằng `flutter pub get`. |
| `--prepare-deps-auto` | Tự chạy lệnh chuẩn bị dependency metadata còn thiếu trước scan, phù hợp khi đã chạy trong sandbox/CI có kiểm soát. |

### Cài tool thiếu và scan lại

- Trước khi scan, công cụ kiểm tra các tool cần thiết/khuyến nghị như `trivy`, `maven`, `gradle`, `node`, `dotnet`, `flutter` theo loại project phát hiện được.
- Nếu thiếu tool và terminal đang tương tác, công cụ hỏi có muốn cài ngay không; nếu đồng ý sẽ dùng package manager hỗ trợ rồi tiếp tục scan.
- Nếu scan vẫn fail vì tool bị thiếu, công cụ hỏi cài tool đó và **scan lại một lần** sau khi cài thành công.
- Với CI/non-interactive, dùng `--install-missing` để tự cài hoặc `--no-install-prompt` để chỉ báo lỗi.
- Công cụ chỉ cài **tool phục vụ scan**. Nếu muốn tự tạo lock/metadata bị thiếu, bật riêng `--prepare-deps` hoặc `--prepare-deps-auto`.

### Chuẩn bị dependency metadata bị thiếu

- `--prepare-deps` chạy trước scan và hỏi xác nhận khi phát hiện source thiếu metadata quan trọng.
- Hiện hỗ trợ Flutter: nếu có `pubspec.yaml` nhưng thiếu `pubspec.lock`, công cụ chạy `flutter pub get` để tạo lockfile rồi mới scan.
- Nếu lệnh chuẩn bị fail do constraint cũ, lỗi được ghi vào `dependency-prepare.log`, `scan-summary.json` và scan vẫn fallback bằng Trivy trên source hiện có.
- `--prepare-deps-auto` bỏ qua bước hỏi, chỉ nên dùng khi source đã tin cậy hoặc chạy trong sandbox.
- Các ecosystem khác như Node/Python/PHP/Ruby/.NET/Go nên được bổ sung từng bước với mode an toàn riêng để tránh chạy lifecycle script không mong muốn.

### PowerShell wrapper — option tương ứng

```powershell
.\run_scan.ps1 -Path "D:\Projects" -MaxWorkers 6 -RecursiveDepth 4
.\run_scan.ps1 -Path "D:\Projects" -TrivyOnly
.\run_scan.ps1 -Path "D:\Projects" -SkipMavenPrebuild
.\run_scan.ps1 -Path "D:\Projects" -DryRun
.\run_scan.ps1 -Path "D:\Projects" -NoDashboard
.\run_scan.ps1 -Path "D:\Projects" -HideCommands -NoColor
.\run_scan.ps1 -Path "D:\Projects" -InstallMissing
.\run_scan.ps1 -Path "D:\Projects" -NoInstallPrompt
.\run_scan.ps1 -Path "D:\Projects" -PrepareDeps
.\run_scan.ps1 -Path "D:\Projects" -PrepareDepsAuto
```

---

## Lưu ý bảo mật & an toàn mã nguồn

- **Không sửa mã nguồn mặc định.** Mọi artifact phụ (`build/`, `target/`, `SBOM.cdx.json`, …) đều nằm trong thư mục output.
- **Gradle:** ưu tiên `cyclonedxBom` nếu task / plugin đã có. Nếu thiếu plugin, công cụ tạo **init script tạm** trong thư mục output để apply CycloneDX plugin theo tài liệu; **không sửa** `build.gradle.kts`.
- **Node.js:** nếu có `package-lock.json` / `npm-shrinkwrap.json`, dùng `cyclonedx-npm --package-lock-only` để **không phụ thuộc** `node_modules`. Nếu là yarn / pnpm / bun, fallback `trivy fs` để đọc lock tương ứng. Nếu không có lock file và cũng không có `node_modules`, report chỉ dựa trên thông tin Trivy đọc được từ mã nguồn — nên commit lock file để quét đầy đủ dependency.
- **Node.js có nhiều lock file:** reconcile SBOM theo **version cao nhất** tìm được trong `package.json`, `package-lock.json`, `npm-shrinkwrap.json`, và `yarn.lock` để tránh lock cũ làm report ra version thấp hơn mã nguồn hiện tại.
- **Frontend monorepo / workspace:** tiếp tục tìm project con trong `apps/`, `packages/`, `frontend/`, … thay vì dừng ở `package.json` cấp cha.
- **Flutter mobile:** quét root Flutter và **bỏ qua** các folder platform `android`, `ios`, `web`, `windows`, `linux`, `macos` như project riêng để tránh báo cáo trùng / lặp version từ thư mục con. Package Flutter trong `packages/` vẫn được phát hiện riêng nếu có `pubspec.yaml`.
- **Maven / Gradle / .NET:** có thể sinh file trong `target/`, `build/`, hoặc output SBOM theo cơ chế của tool gốc.
- **Mọi command đều chạy bằng argument list** (qua `subprocess.run([...])`), **không dùng shell string concat** — tránh lỗi injection khi `path` chứa ký tự đặc biệt.

---

## Lỗi thường gặp

### Frontend quét thiếu package

Kiểm tra theo thứ tự:

1. Chạy `--dry-run` để xem công cụ có phát hiện đủ các app con (`apps/web`, `packages/ui`, `frontend/admin`, …) hay không.
2. **Nên commit lock file** (`package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock`, `pnpm-lock.yaml`, `bun.lock`, `bun.lockb`). Nếu chỉ có `package.json`, công cụ không biết đầy đủ transitive dependency / version.
3. Nếu app frontend nằm sâu hơn 5 cấp folder, tăng `--recursive-depth`.
4. Nếu dùng npm và có `package-lock.json`, công cụ sẽ dùng `--package-lock-only` — **không cần** `node_modules`.
5. Nếu terminal / CI set `NODE_ENV=production`, Node SBOM generator vẫn được chạy với `NODE_ENV` được unset để không tự omit `devDependencies`.

### License quét thiếu package

Kiểm tra theo thứ tự:

1. Mở `services\<service>\license-normalize.log` — dòng `Components total` và `Components with licenses` cho biết SBOM có bao nhiêu component / license.
2. Nếu SBOM có license nhưng Trivy không trả hết trong `license.json`, công cụ **tự thêm** các dòng thiếu từ `SBOM.cdx-fix.json` vào `report.json` và `license.json`.
3. Nếu component **không có license** trong SBOM, report sẽ hiện `LicenseRef-No-Declared-License` với severity `UNKNOWN` để reviewer xử lý thủ công.
4. Nếu `Components total` đã thiếu package, nguyên nhân nằm ở **bước sinh SBOM / generator** của ecosystem — không phải report.

### `trivy not found in PATH`

Cài Trivy và mở terminal mới:

```bash
trivy --version
```

Hướng dẫn cài đặt chính thức: <https://trivy.dev/latest/getting-started/installation/>

### Không phát hiện được project

Chạy dry-run:

```bash
python autoscan.py "D:/Projects" --dry-run --recursive-depth 5
```

- Nếu vẫn không thấy, kiểm tra folder có file marker (`pom.xml`, `package.json`, `.csproj`, `go.mod`, …).
- Nếu root là folder cha chứa nhiều service, các folder cấp 1 không có marker sẽ hiện là `[unknown]` và vẫn được quét bằng `trivy fs`.

### Maven / Gradle / Node / .NET generator fail

Công cụ sẽ fallback về `trivy fs` nếu có thể. Xem chi tiết trong:

```text
scan-results\<timestamp>\services\<service>\scan.log
```

### Nút Export Excel không hoạt động

Report HTML đang tải thư viện `xlsx-js-style` từ CDN. Máy cần truy cập Internet, hoặc cần cache CDN sẵn trong môi trường nội bộ.

---

## Giấy phép

Công cụ nội bộ — vui lòng tham khảo policy của tổ chức bạn về cách sử dụng và phân phối.
