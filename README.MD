# Auto Scan Vulnerability & License

Tool nay tu dong detect loai source-code, tao SBOM, scan dependency vulnerability va license bang Trivy, sau do sinh HTML report tong hop co export Excel.

Muc tieu: chi can chay mot lenh tren folder source, tool tu xu ly phan con lai.

## Lenh chay nhanh

Chay tren Windows/PowerShell:

```powershell
.\run_scan.ps1 -Path "D:\Projects"
```

Hoac chay truc tiep bang Python:

```powershell
python autoscan.py "D:\Projects"
```

Neu `D:\Projects` la mot project, tool scan mot project. Neu `D:\Projects` la folder cha chua nhieu service, tool tu scan tung service va merge report.

Ket qua cuoi cung:

```text
D:\Projects\scan-results\consolidated-report.html
D:\Projects\scan-results\scan-summary.json
```

## Kien truc file

```text
auto-scan-vuln-lic/
  autoscan.py
  run_scan.ps1
  README.MD

  autoscan/
    __init__.py
    batch.py
    config.py
    detector.py
    license_normalizer.py
    license_rules.py
    models.py
    scanner.py
    sbom_generator.py
    trivy_runner.py
    utils.py
    reporting/
      __init__.py
      merge_report.py
      reports.py
      single_report.py
```

Vai tro chinh:

| File | Cong dung |
| --- | --- |
| `autoscan.py` | Entrypoint chinh, nhan path va dieu phoi scan. |
| `run_scan.ps1` | Wrapper PowerShell de chay mot lenh tren Windows. |
| `autoscan/detector.py` | Tu detect Maven, Gradle, Node, Flutter, .NET, Python, Go, PHP, Ruby. |
| `autoscan/sbom_generator.py` | Tao SBOM theo tung loai source, fallback ve `trivy fs`. |
| `autoscan/license_normalizer.py` | Chuan hoa license SBOM ve SPDX/LicenseRef. |
| `autoscan/license_rules.py` | Bo rule normalize license tu ten vendor/free-text ve SPDX ID. |
| `autoscan/license_inventory.py` | Bu license tu SBOM vao report neu Trivy khong tra du license rows. |
| `autoscan/trivy_runner.py` | Chay Trivy va tao output JSON/TXT. |
| `autoscan/scanner.py` | Scan mot project/service. |
| `autoscan/batch.py` | Scan nhieu project/service song song va tao report tong hop. |
| `autoscan/reporting/single_report.py` | Engine sinh report HTML tung service. |
| `autoscan/reporting/merge_report.py` | Engine sinh report HTML tong hop. |

## Yeu cau cai dat

Bat buoc:

- Python 3
- Trivy trong `PATH`
- PowerShell neu dung `run_scan.ps1`

Khuyen nghi de SBOM chinh xac hon theo tung ecosystem:

- Maven project: `mvn`
- Gradle project: `gradlew` trong project hoac `gradle` trong `PATH`
- Node.js project: `node`, `npm`, `npx`
- .NET project: `dotnet`, tool se tu cai `dotnet-CycloneDX` neu thieu
- Flutter project: `flutter`

Kiem tra nhanh:

```powershell
python --version
trivy --version
```

## Loai source duoc detect

| Loai | Marker |
| --- | --- |
| Maven | `pom.xml` |
| Gradle | `build.gradle`, `build.gradle.kts`, `settings.gradle`, `gradlew` |
| Node.js | `package.json`, `package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock`, `pnpm-lock.yaml`, `bun.lock`, `bun.lockb` |
| Flutter | `pubspec.yaml` |
| .NET | `.sln`, `.csproj` |
| Python | `requirements.txt`, `pyproject.toml`, `Pipfile`, `poetry.lock` |
| Go | `go.mod` |
| PHP | `composer.json`, `composer.lock` |
| Ruby | `Gemfile`, `Gemfile.lock` |

Neu khong co generator rieng hoac generator rieng bi fail, tool fallback ve:

```powershell
trivy fs --format cyclonedx
```

## Luong scan

Voi moi project/service:

1. Detect loai source.
2. Luon tao moi SBOM cho lan scan hien tai, khong dung lai SBOM co san trong source de tranh ket qua bi cu khi re-scan.
3. Tao SBOM theo ecosystem neu co tool phu hop:
   - Maven: `mvn org.cyclonedx:cyclonedx-maven-plugin:makeAggregateBom -DskipTests`
   - Gradle: `gradlew cyclonedxBom` hoac `gradle cyclonedxBom`; neu thieu plugin, tool dung init script tam de apply `org.cyclonedx.bom` version `2.3.1` theo document ma khong sua source.
   - Node.js npm lock: `npx --yes @cyclonedx/cyclonedx-npm --ignore-npm-errors --package-lock-only`
   - Node.js yarn/pnpm/bun lock: fallback `trivy fs`
   - .NET: `dotnet-CycloneDX <project> -j`; neu thieu tool va co `dotnet`, tool tu chay `dotnet tool install --global CycloneDX`.
   - Flutter/Python/Go/PHP/Ruby/unknown: fallback `trivy fs`
   - Neu generator rieng fail hoac khong tao ra SBOM moi, fallback `trivy fs --format cyclonedx`.
4. Normalize license thanh `SBOM.cdx-fix.json`.
5. Chay Trivy:
   - `report.json`: scan chung `vuln,license`
   - `license.json`: license-only JSON
   - `license.txt`: license-only TXT
   - `vuln.json`: vulnerability-only JSON
6. Doi chieu license trong `SBOM.cdx-fix.json` voi `report.json`/`license.json`; neu Trivy tra thieu package license, tool tu bo sung tu SBOM. Component khong khai bao license se hien `LicenseRef-No-Declared-License` de khong bi mat im lang.
7. Sinh:
   - `report.html`
   - `report-vuln.html`
8. Merge tat ca service thanh `consolidated-report.html`.

## Output

Vi du khi chay:

```powershell
.\run_scan.ps1 -Path "D:\Projects"
```

Output:

```text
D:\Projects\scan-results\
  consolidated-report.html
  scan-summary.json
  20260603-153000\
    consolidated-report.html
    scan-summary.json
    services\
      service-a\
        SBOM.cdx.json
        SBOM.cdx-fix.json
        license-normalize.log
        report.json
        report.html
        report-vuln.html
        license.json
        license.txt
        vuln.json
        scan.log
```

File quan trong nhat:

- `scan-results\consolidated-report.html`: report tong hop cuoi cung.
- `scan-results\scan-summary.json`: summary may-doc-duoc, gom OK/FAIL, count vuln/license, path output tung service.
- `services\<service>\scan.log`: log command chi tiet de debug.
- `services\<service>\license-normalize.log`: thong ke so component co license trong SBOM va cac license da normalize.

## Tuy chon CLI

```powershell
python autoscan.py "D:\Projects" --max-workers 6
```

```powershell
python autoscan.py "D:\Projects" --recursive-depth 4
```

```powershell
python autoscan.py "D:\Projects" --trivy-only
```

```powershell
python autoscan.py "D:\Projects" --dry-run
```

Y nghia:

| Option | Cong dung |
| --- | --- |
| `--max-workers` | So project scan song song. |
| `--recursive-depth` | Do sau tim project con/nested, huu ich voi monorepo hoac frontend nam trong `apps/`, `packages/`, `frontend/`. |
| `--trivy-only` | Bo qua generator Maven/Gradle/Node/.NET, chi dung `trivy fs`. |
| `--dry-run` | Chi detect project, khong chay Trivy hay tool ngoai. |
| `--output` | Doi folder output mac dinh. |

PowerShell wrapper co option tuong ung:

```powershell
.\run_scan.ps1 -Path "D:\Projects" -MaxWorkers 6 -RecursiveDepth 4
.\run_scan.ps1 -Path "D:\Projects" -TrivyOnly
.\run_scan.ps1 -Path "D:\Projects" -DryRun
```

## Su dung report

Mo file:

```text
scan-results\consolidated-report.html
```

Report co:

- Overview vulnerability/license.
- Bang vulnerability.
- Bang license.
- Filter theo package, severity, category, action.
- Export Excel.

Trong Excel:

- Package co nhieu dong merge duoc dua len dau.
- Cot `Severity` duoc to mau:
  - `CRITICAL`: do dam
  - `HIGH`: do
  - `MEDIUM`: vang
  - `LOW`: xanh la
- Sheet `License` bo cot `Category` va `Action`.

## Luu y bao mat va an toan source

- Tool khong tu sua source code mac dinh.
- Gradle: tool uu tien `cyclonedxBom` neu task/plugin da co. Neu thieu plugin, tool tao init script tam trong folder output de apply CycloneDX plugin theo document; khong sua `build.gradle.kts`.
- Node.js: neu co `package-lock.json`/`npm-shrinkwrap.json`, tool dung `cyclonedx-npm --package-lock-only` de khong phu thuoc `node_modules`. Neu la yarn/pnpm/bun, tool fallback `trivy fs` de doc lock file tuong ung. Neu khong co lock file va cung khong co `node_modules`, report chi co the dua tren thong tin Trivy doc duoc tu source; nen commit lock file de scan du dependency hon.
- Frontend monorepo/workspace: tool se tiep tuc tim project con trong `apps/`, `packages/`, `frontend/`, ... thay vi dung o `package.json` cap cha.
- Maven/Gradle/.NET co the tao file trong `target/`, `build/`, hoac output SBOM theo co che cua tool goc.
- Tat ca command duoc chay bang argument list, khong dung shell string concat.

## Loi thuong gap

### Frontend scan thieu package

Kiem tra cac diem sau:

- Chay `--dry-run` de xem tool co detect du cac app con nhu `apps/web`, `packages/ui`, `frontend/admin` hay khong.
- Nen commit lock file (`package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock`, `pnpm-lock.yaml`, `bun.lock`, `bun.lockb`). Neu chi co `package.json`, tool khong the biet day du transitive dependency/version.
- Neu app frontend nam qua sau hon 5 cap folder, tang `--recursive-depth`.
- Neu dung npm va co `package-lock.json`, tool se dung `--package-lock-only`, nen khong can `node_modules`.
- Neu terminal/CI set `NODE_ENV=production`, Node SBOM generator van duoc chay voi `NODE_ENV` unset de khong tu omit `devDependencies`.

### License scan thieu package

Kiem tra theo thu tu:

- Mo `services\<service>\license-normalize.log`: dong `Components total` va `Components with licenses` cho biet SBOM co bao nhieu component/license.
- Neu SBOM co license nhung Trivy khong tra het trong `license.json`, tool se tu them cac dong thieu tu `SBOM.cdx-fix.json` vao `report.json` va `license.json`.
- Neu component khong co license trong SBOM, report se hien `LicenseRef-No-Declared-License` voi severity `UNKNOWN` de reviewer xu ly thu cong.
- Neu `Components total` da thieu package, nguyen nhan nam o buoc tao SBOM/generator cua ecosystem, khong phai report.

### `trivy not found in PATH`

Cai Trivy va mo terminal moi:

```powershell
trivy --version
```

### Khong detect duoc project

Chay dry-run:

```powershell
python autoscan.py "D:\Projects" --dry-run --recursive-depth 5
```

Neu van khong thay, kiem tra folder co file marker nhu `pom.xml`, `package.json`, `.csproj`, `go.mod`, ...

### Maven/Gradle/Node/.NET generator fail

Tool se fallback ve `trivy fs` neu co the. Xem chi tiet trong:

```text
scan-results\<timestamp>\services\<service>\scan.log
```

### Nut Export Excel khong hoat dong

Report HTML dang tai thu vien `xlsx-js-style` tu CDN. May can truy cap internet hoac can cache CDN san.
