from __future__ import annotations

import os
import time
from pathlib import Path

from .models import Project, CommandRecord
from .utils import copy_file, ensure_dir, first_existing_tool, run_command, tool_exists


class SbomGenerationError(RuntimeError):
    pass


def _is_under(path: Path, parent: Path) -> bool:
    try:
        path.resolve().relative_to(parent.resolve())
        return True
    except ValueError:
        return False


def _latest_matching_file(
    root: Path,
    names: tuple[str, ...],
    *,
    modified_after: float | None = None,
    exclude_roots: tuple[Path, ...] = (),
) -> Path | None:
    matches: list[Path] = []
    for name in names:
        for path in root.rglob(name):
            if not path.is_file():
                continue
            if any(_is_under(path, excluded) for excluded in exclude_roots):
                continue
            if modified_after is not None and path.stat().st_mtime < modified_after:
                continue
            matches.append(path)
    if not matches:
        return None
    return max(matches, key=lambda p: p.stat().st_mtime)


def _copy_or_raise(src: Path | None, output_sbom: Path) -> Path:
    if not src or not src.is_file():
        raise SbomGenerationError("SBOM was not generated")
    return copy_file(src, output_sbom)


def _run_trivy_fs(project: Project, output_sbom: Path, log_file: Path) -> tuple[Path, str, list[CommandRecord]]:
    if not tool_exists("trivy"):
        raise SbomGenerationError("trivy not found in PATH")
    command = ["trivy", "fs", "--format", "cyclonedx", "--output", str(output_sbom), str(project.path)]
    record, _, _ = run_command(command, cwd=project.path, log_file=log_file)
    if record.returncode != 0 or not output_sbom.is_file():
        raise SbomGenerationError("trivy fs failed to generate SBOM")
    return output_sbom, "generated-trivy-fs", [record]


def _maven_command(project: Project) -> list[str] | None:
    if os.name == "nt" and (project.path / "mvnw.cmd").is_file():
        return [str(project.path / "mvnw.cmd")]
    if (project.path / "mvnw").is_file():
        mvnw = project.path / "mvnw"
        try:
            mode = mvnw.stat().st_mode
            mvnw.chmod(mode | 0o111)
        except OSError:
            pass
        return [str(mvnw)]
    mvn = first_existing_tool(("mvn", "mvn.cmd"))
    if mvn:
        return [mvn]
    return None


def _run_maven(project: Project, output_sbom: Path, log_file: Path) -> tuple[Path | None, list[CommandRecord]]:
    command = _maven_command(project)
    if not command:
        return None, []
    started_at = time.time()
    command = command + [
        "org.cyclonedx:cyclonedx-maven-plugin:makeAggregateBom",
        "-DskipTests",
        "-DoutputFormat=json",
        f"-DoutputDirectory={output_sbom.parent}",
        "-DoutputName=SBOM.cdx",
    ]
    record, _, _ = run_command(command, cwd=project.path, log_file=log_file)
    if record.returncode == 0 and output_sbom.is_file() and output_sbom.stat().st_mtime >= started_at:
        return output_sbom, [record]
    after = _latest_matching_file(
        project.path,
        ("bom.json", "*.cdx.json"),
        modified_after=started_at,
        exclude_roots=(output_sbom.parent,),
    )
    if record.returncode == 0 and after:
        return _copy_or_raise(after, output_sbom), [record]
    return None, [record]


def _gradle_command(project: Project) -> list[str] | None:
    if os.name == "nt" and (project.path / "gradlew.bat").is_file():
        return [str(project.path / "gradlew.bat"), "cyclonedxBom"]
    if (project.path / "gradlew").is_file():
        gradlew = project.path / "gradlew"
        try:
            mode = gradlew.stat().st_mode
            gradlew.chmod(mode | 0o111)
        except OSError:
            pass
        return [str(gradlew), "cyclonedxBom"]
    gradle = first_existing_tool(("gradle", "gradle.bat"))
    if gradle:
        return [gradle, "cyclonedxBom"]
    return None


def _run_gradle(project: Project, output_sbom: Path, log_file: Path) -> tuple[Path | None, list[CommandRecord]]:
    command = _gradle_command(project)
    if not command:
        return None, []
    records: list[CommandRecord] = []
    started_at = time.time()
    record, _, _ = run_command(command, cwd=project.path, log_file=log_file)
    records.append(record)
    generated = (
        _latest_matching_file(
            project.path / "build",
            ("*.cdx.json", "bom.json", "application.cdx.json"),
            modified_after=started_at,
        )
        if (project.path / "build").exists()
        else None
    )
    if record.returncode == 0 and generated:
        return _copy_or_raise(generated, output_sbom), records

    init_script = output_sbom.parent / "cyclonedx-init.gradle"
    init_script.write_text(
        """
initscript {
    repositories { mavenCentral() }
    dependencies { classpath 'org.cyclonedx:cyclonedx-gradle-plugin:2.3.1' }
}

allprojects {
    apply plugin: 'org.cyclonedx.bom'
}
""".strip()
        + "\n",
        encoding="utf-8",
    )
    started_at = time.time()
    init_command = [command[0], "--init-script", str(init_script), "cyclonedxBom"]
    init_record, _, _ = run_command(init_command, cwd=project.path, log_file=log_file)
    records.append(init_record)
    generated = (
        _latest_matching_file(
            project.path / "build",
            ("*.cdx.json", "bom.json", "application.cdx.json"),
            modified_after=started_at,
        )
        if (project.path / "build").exists()
        else None
    )
    if init_record.returncode == 0 and generated:
        return _copy_or_raise(generated, output_sbom), records
    return None, records


def _run_node(project: Project, output_sbom: Path, log_file: Path) -> tuple[Path | None, list[CommandRecord]]:
    npx = first_existing_tool(("npx", "npx.cmd"))
    if not npx:
        return None, []
    npm_lock_exists = (project.path / "package-lock.json").is_file() or (project.path / "npm-shrinkwrap.json").is_file()
    non_npm_lock_exists = any(
        (project.path / name).is_file()
        for name in ("yarn.lock", "pnpm-lock.yaml", "bun.lock", "bun.lockb")
    )
    if non_npm_lock_exists and not npm_lock_exists:
        return None, []
    if not npm_lock_exists and not (project.path / "node_modules").is_dir():
        return None, []

    temp_output = output_sbom.parent / "sbom-node.json"
    temp_output.unlink(missing_ok=True)
    command = [
        npx,
        "--yes",
        "@cyclonedx/cyclonedx-npm",
        "--ignore-npm-errors",
    ]
    if npm_lock_exists:
        command.append("--package-lock-only")
    command.extend([
        "--output-file",
        str(temp_output),
        str(project.path / "package.json"),
    ])
    env = os.environ.copy()
    env.pop("NODE_ENV", None)
    record, _, _ = run_command(command, cwd=project.path, log_file=log_file, env=env)
    if record.returncode == 0 and temp_output.is_file():
        return _copy_or_raise(temp_output, output_sbom), [record]
    return None, [record]


def _run_dotnet(project: Project, output_sbom: Path, log_file: Path) -> tuple[Path | None, list[CommandRecord]]:
    cyclonedx = first_existing_tool(("dotnet-CycloneDX", "dotnet-CycloneDX.exe"))
    records: list[CommandRecord] = []
    if not cyclonedx:
        dotnet = first_existing_tool(("dotnet", "dotnet.exe"))
        if not dotnet:
            return None, records
        install_record, _, _ = run_command([dotnet, "tool", "install", "--global", "CycloneDX"], cwd=project.path, log_file=log_file)
        records.append(install_record)
        cyclonedx = first_existing_tool(("dotnet-CycloneDX", "dotnet-CycloneDX.exe"))
        if not cyclonedx:
            dotnet_tools = Path.home() / ".dotnet" / "tools"
            candidate = dotnet_tools / ("dotnet-CycloneDX.exe" if os.name == "nt" else "dotnet-CycloneDX")
            if candidate.is_file():
                cyclonedx = str(candidate)
        if not cyclonedx:
            return None, records
    targets = sorted(project.path.glob("*.sln")) + sorted(project.path.glob("*.csproj"))
    target = targets[0] if targets else project.path
    started_at = time.time()
    command = [cyclonedx, str(target), "-j"]
    record, _, _ = run_command(command, cwd=project.path, log_file=log_file)
    records.append(record)
    after = _latest_matching_file(
        project.path,
        ("bom.json", "*.cdx.json"),
        modified_after=started_at,
        exclude_roots=(output_sbom.parent,),
    )
    if record.returncode == 0 and after:
        return _copy_or_raise(after, output_sbom), records
    return None, records


def _prepare_flutter(project: Project, log_file: Path) -> list[CommandRecord]:
    if (project.path / "pubspec.lock").is_file():
        return []
    flutter = first_existing_tool(("flutter", "flutter.bat"))
    if not flutter:
        return []
    record, _, _ = run_command([flutter, "pub", "get"], cwd=project.path, log_file=log_file)
    return [record]


def generate_sbom(project: Project, output_dir: Path, log_file: Path, trivy_only: bool = False) -> tuple[Path, str, list[CommandRecord]]:
    ensure_dir(output_dir)
    output_sbom = output_dir / "SBOM.cdx.json"
    output_sbom.unlink(missing_ok=True)
    records: list[CommandRecord] = []

    if not trivy_only:
        if project.kind == "maven":
            generated, cmd_records = _run_maven(project, output_sbom, log_file)
            records.extend(cmd_records)
            if generated:
                return generated, "generated-maven-cyclonedx", records
        elif project.kind == "gradle":
            generated, cmd_records = _run_gradle(project, output_sbom, log_file)
            records.extend(cmd_records)
            if generated:
                return generated, "generated-gradle-cyclonedx", records
        elif project.kind == "node":
            generated, cmd_records = _run_node(project, output_sbom, log_file)
            records.extend(cmd_records)
            if generated:
                return generated, "generated-node-cyclonedx", records
        elif project.kind == "dotnet":
            generated, cmd_records = _run_dotnet(project, output_sbom, log_file)
            records.extend(cmd_records)
            if generated:
                return generated, "generated-dotnet-cyclonedx", records
        elif project.kind == "flutter":
            records.extend(_prepare_flutter(project, log_file))

    sbom, status, trivy_records = _run_trivy_fs(project, output_sbom, log_file)
    records.extend(trivy_records)
    return sbom, status, records
