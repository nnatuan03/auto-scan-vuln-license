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

Neu `D:\Projects` la mot project, tool scan mot project. Neu `D:\Projects` la folder cha chua nhieu service, tool tu scan tung service va merge report. Folder service cap 1 nao khong detect duoc marker nhu `pom.xml`/`package.json` van se duoc scan bang `trivy fs` voi kind `unknown`, de tranh bo sot folder.

Khi chay, terminal se hien dashboard tien do:

```text
Auto Scan Dashboard
===================
Stage    : scanning
Progress : [###############---------------] 5/10 ( 50.0%)
Status   : DONE=5 OK=5 FAIL=0 RUNNING=5
Elapsed  : 03:20
ETA      : 03:20
```

Dashboard cap nhat sau moi service hoan tat va khi bat dau merge report.
Moi command ngoai nhu Maven, Gradle, npm/npx, Flutter, Trivy se duoc in ra terminal voi mau rieng:

```text
[RUN] trivy sbom --scanners vuln,license --format json ...
[OK ] exit=0 time=1.24s trivy sbom --scanners vuln,license --format json ...
[FAIL] exit=1 time=0.42s gradle cyclonedxBom
```

Ket qua cuoi cung:

```text
D:\Projects\scan-results\consolidated-report.html
D:\Projects\scan-results\scan-summary.json
D:\Projects\scan-results\debug-report.md
D:\Projects\scan-results\debug-report.json
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
    debug_report.py
    detector.py
    license_normalizer.py
    license_rules.py
    models.py
    progress.py
    scanner.py
    sbom_generator.py
    terminal.py
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
| `autoscan/debug_report.py` | Tao debug report de doi chieu document, detect marker, command, SBOM/license count. |
| `autoscan/progress.py` | Dashboard terminal hien tien do %, elapsed va ETA trong luc scan. |
| `autoscan/terminal.py` | In command, status va mau terminal/PowerShell. |
| `autoscan/reporting/single_report.py` | Engine sinh report HTML tung service. |
| `autoscan/reporting/merge_report.py` | Engine sinh report HTML tong hop. |

## Yeu cau cai dat

Bat buoc:

- Python 3
- Trivy trong `PATH`
- PowerShell neu dung `run_scan.ps1`

Khuyen nghi de SBOM chinh xac hon theo tung ecosystem:

- Maven project: `mvnw.cmd`/`mvnw` trong project hoac `mvn` trong `PATH`
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
| Unknown | Folder service cap 1 khong co marker, fallback `trivy fs` |

Neu khong co generator rieng hoac generator rieng bi fail, tool fallback ve:

```powershell
trivy fs --format cyclonedx
```

## Luong scan

Voi moi project/service:

1. Detect loai source.
2. Luon tao moi SBOM cho lan scan hien tai, khong dung lai SBOM co san trong source de tranh ket qua bi cu khi re-scan.
3. Tao SBOM theo ecosystem neu co tool phu hop:
   - Maven: `mvnw.cmd`/`mvnw` neu co, fallback `mvn org.cyclonedx:cyclonedx-maven-plugin:makeAggregateBom -DskipTests`
   - Gradle: `gradlew cyclonedxBom` hoac `gradle cyclonedxBom`; neu thieu plugin, tool dung init script tam de apply `org.cyclonedx.bom` version `2.3.1` theo document ma khong sua source.
   - Node.js npm lock: `npx --yes @cyclonedx/cyclonedx-npm --ignore-npm-errors --package-lock-only`
   - Node.js yarn/pnpm/bun lock: fallback `trivy fs`
   - .NET: `dotnet-CycloneDX <project> -j`; neu thieu tool va co `dotnet`, tool tu chay `dotnet tool install --global CycloneDX`.
   - Flutter/Python/Go/PHP/Ruby/unknown: fallback `trivy fs`
   - Neu generator rieng fail hoac khong tao ra SBOM moi, fallback `trivy fs --format cyclonedx`.
4. Reconcile version trong SBOM voi version moi nhat tim duoc trong source/lock file hien co. Vi du Node co ca `package-lock.json` va `yarn.lock`, neu SBOM ra `1.80.0` nhung `package.json`/`yarn.lock` dang co `1.84.0`, tool se cap nhat SBOM len `1.84.0` truoc khi scan. Tool khong tu query registry de upgrade dependency ngoai source.
5. Normalize license thanh `SBOM.cdx-fix.json`.
6. Chay Trivy nhanh:
   - Tool chi chay 1 lenh `trivy sbom --scanners vuln,license --format json` de tao `report.json`
   - Tu `report.json`, tool tach ra `license.json`, `license.txt`, va `vuln.json`
   - Cach nay giu du output nhu cu nhung giam so lan goi Trivy tren moi service
7. Doi chieu license trong `SBOM.cdx-fix.json` voi `report.json`/`license.json`; neu Trivy tra thieu package license, tool tu bo sung tu SBOM. Component khong khai bao license se hien `LicenseRef-No-Declared-License` de khong bi mat im lang.
8. Sinh:
   - `report.html`
   - `report-vuln.html`
9. Merge tat ca service thanh `consolidated-report.html`.
10. Sinh `debug-report.md/json` de doi chieu voi document va debug tung service.

## Doi chieu voi document ITS

Tool dang cover cac case license/dependency scan trong document, tru cac phan ban da loai khoi scope:

| Case trong document | Cach tool cover |
| --- | --- |
| Trivy dependency vulnerability scan | Chay `trivy sbom --scanners vuln --format json`, sau do sinh `report-vuln.html`. |
| Gradle license scan | Chay `gradlew/gradle cyclonedxBom`; neu thieu plugin thi dung init script tam voi `org.cyclonedx.bom` version `2.3.1`. |
| Maven license scan | Chay `mvnw/mvn org.cyclonedx:cyclonedx-maven-plugin:makeAggregateBom`. |
| Node.js npm/package-lock license scan | Chay `npx --yes @cyclonedx/cyclonedx-npm --ignore-npm-errors`; neu co lock npm thi dung `--package-lock-only`. |
| .NET license scan | Tu cai `CycloneDX` neu thieu, roi chay `dotnet-CycloneDX` tren `.sln`/`.csproj`. |
| Normalize SBOM truoc khi scan license | Tao `SBOM.cdx-fix.json` bang module normalize noi bo. |
| License TXT/JSON | Tao `license.txt` va `license.json` cho tung service. |

Khac biet co chu dich:

- SBOM duoc tao moi trong `scan-results\<timestamp>` moi lan scan, khong ghi/dependency vao `third-party`, de tranh re-scan dung SBOM cu.
- Gradle khong tu sua `build.gradle`/`build.gradle.kts`; init script tam chi nam trong output.
- `report-vuln.html` duoc sinh tu `vuln.json` bang template noi bo thay vi `html.tpl` cua Trivy.
- SonarQ/SonarQube va Script CI/CD/Jenkins/email dang exclude theo scope ban da chot.

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
  debug-report.md
  debug-report.json
  20260603-153000\
    consolidated-report.html
    scan-summary.json
    debug-report.md
    debug-report.json
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
- `scan-results\debug-report.md`: debug report de doc nhanh, gom doi chieu document, service detect, command da chay, count SBOM/license.
- `scan-results\debug-report.json`: debug report dang JSON de gui/parse lai khi can trace sau.
- `services\<service>\scan.log`: log command chi tiet de debug.
- `services\<service>\license-normalize.log`: thong ke so component co license trong SBOM va cac license da normalize.

## Debug khi ket qua bi thieu/sai

Chay dry-run truoc de xem tool detect du bao nhieu service:

```powershell
.\run_scan.ps1 -Path "D:\Projects" -DryRun
```

Sau khi scan xong, mo:

```text
D:\Projects\scan-results\debug-report.md
```

Trong file debug, kiem tra theo thu tu:

- `Document Coverage`: case nao dang covered, case nao khac document co chu dich, case nao excluded.
- `Services`: service nao duoc detect, kind gi, marker nao, SBOM tao bang generator nao.
- `Commands`: command thuc te da chay va exit code.
- `Retry/fallback note` va `Command failures`: command fail/success tiep theo, kem stderr tail, dung de xem ly do fallback.
- `Version updates`: so component trong SBOM duoc nang len version moi hon tim thay trong source/lock file.
- `fixed components`: so component trong `SBOM.cdx-fix.json`; neu so nay da thieu thi loi nam o buoc tao SBOM.
- `SBOM license rows` va `Trivy licenses`: neu SBOM co du license rows nhung Trivy thieu, tool se backfill vao report.

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

```powershell
python autoscan.py "D:\Projects" --no-dashboard
```

```powershell
python autoscan.py "D:\Projects" --hide-commands --no-color
```

Y nghia:

| Option | Cong dung |
| --- | --- |
| `--max-workers` | So project scan song song. |
| `--recursive-depth` | Do sau tim project con/nested, huu ich voi monorepo hoac frontend nam trong `apps/`, `packages/`, `frontend/`. |
| `--trivy-only` | Bo qua generator Maven/Gradle/Node/.NET, chi dung `trivy fs`. |
| `--dry-run` | Chi detect project, khong chay Trivy hay tool ngoai. |
| `--output` | Doi folder output mac dinh. |
| `--no-dashboard` | Tat dashboard tien do trong terminal neu muon log gon. |
| `--hide-commands` | Khong in tung command ra terminal. |
| `--no-color` | Tat mau terminal. |

PowerShell wrapper co option tuong ung:

```powershell
.\run_scan.ps1 -Path "D:\Projects" -MaxWorkers 6 -RecursiveDepth 4
.\run_scan.ps1 -Path "D:\Projects" -TrivyOnly
.\run_scan.ps1 -Path "D:\Projects" -DryRun
.\run_scan.ps1 -Path "D:\Projects" -NoDashboard
.\run_scan.ps1 -Path "D:\Projects" -HideCommands -NoColor
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
- Node.js co nhieu lock file: tool reconcile SBOM theo version cao nhat tim duoc trong `package.json`, `package-lock.json`, `npm-shrinkwrap.json`, va `yarn.lock` de tranh lock file cu lam report ra version thap hon source hien tai.
- Frontend monorepo/workspace: tool se tiep tuc tim project con trong `apps/`, `packages/`, `frontend/`, ... thay vi dung o `package.json` cap cha.
- Flutter mobile: tool scan root Flutter va bo qua cac folder platform `android`, `ios`, `web`, `windows`, `linux`, `macos` nhu project rieng de tranh report trung/lap version tu thu muc con. Package Flutter trong `packages/` van duoc detect rieng neu co `pubspec.yaml`.
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

Neu root la folder cha chua nhieu service, cac folder cap 1 khong co marker se hien la `[unknown]` va van duoc scan bang `trivy fs`.

### Maven/Gradle/Node/.NET generator fail

Tool se fallback ve `trivy fs` neu co the. Xem chi tiet trong:

```text
scan-results\<timestamp>\services\<service>\scan.log
```

### Nut Export Excel khong hoat dong

Report HTML dang tai thu vien `xlsx-js-style` tu CDN. May can truy cap internet hoac can cache CDN san.
