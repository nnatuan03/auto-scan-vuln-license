from pathlib import Path

from autoscan.models import Project, CommandRecord
from autoscan.sbom_generator import generate_sbom
from autoscan.trivy_runner import scan_filesystem_target


def _record(command):
    return CommandRecord(command=command, cwd='.', returncode=0, duration_seconds=0)


def test_generate_sbom_uses_parent_cwd_for_single_file(tmp_path, monkeypatch):
    target = tmp_path / 'requirements.txt'
    target.write_text('flask==2.0.0', encoding='utf-8')
    output_dir = tmp_path / 'out'
    calls = []

    monkeypatch.setattr('autoscan.sbom_generator.tool_exists', lambda name: True)

    def fake_run(command, cwd, log_file):
        calls.append((command, cwd))
        Path(command[command.index('--output') + 1]).write_text('{"bomFormat":"CycloneDX","components":[]}', encoding='utf-8')
        return _record(command), '', ''

    monkeypatch.setattr('autoscan.sbom_generator.run_command', fake_run)

    generate_sbom(Project(target, target.name, 'file', [target.name]), output_dir, output_dir / 'scan.log', trivy_only=True)

    assert calls[0][0][:4] == ['trivy', 'fs', '--format', 'cyclonedx']
    assert calls[0][1] == tmp_path
    assert calls[0][0][-1] == str(target)


def test_scan_filesystem_target_runs_all_source_scanners(tmp_path, monkeypatch):
    target = tmp_path / 'app'
    target.mkdir()
    output_dir = tmp_path / 'out'
    calls = []

    monkeypatch.setattr('autoscan.trivy_runner.tool_exists', lambda name: True)

    def fake_run(command, cwd, log_file):
        calls.append((command, cwd))
        Path(command[command.index('--output') + 1]).write_text('{"Results":[]}', encoding='utf-8')
        return _record(command), '', ''

    monkeypatch.setattr('autoscan.trivy_runner.run_command', fake_run)

    outputs, counts, records = scan_filesystem_target(target, output_dir, output_dir / 'scan.log')

    assert outputs['filesystem_report_json'] == output_dir / 'filesystem-report.json'
    assert counts == {'vulnerabilities': 0, 'licenses': 0, 'misconfigurations': 0, 'secrets': 0}
    assert records[0].command[:7] == ['trivy', 'fs', '--scanners', 'vuln,license,secret,misconfig', '--license-full', '--format', 'json']
    assert calls[0][1] == target

from autoscan.batch import scan_all
from autoscan.detector import detect_project


def test_detect_project_recognizes_trivy_fallback_ecosystems(tmp_path):
    cases = {
        'rust': ('rust-app', 'Cargo.lock'),
        'iac': ('infra', 'main.tf'),
        'python': ('python-app', 'uv.lock'),
        'dotnet': ('dotnet-app', 'packages.config'),
        'java': ('java-app', 'app.jar'),
        'swift': ('swift-app', 'Package.resolved'),
        'cocoapods': ('ios-app', 'Podfile.lock'),
        'julia': ('julia-app', 'Manifest.toml'),
        'cpp': ('cpp-app', 'vcpkg.json'),
    }

    for expected_kind, (folder, marker) in cases.items():
        project_path = tmp_path / folder
        project_path.mkdir()
        (project_path / marker).write_text('', encoding='utf-8')
        assert detect_project(project_path).kind == expected_kind


def test_scan_all_accepts_single_file_in_dry_run(tmp_path):
    target = tmp_path / 'requirements.txt'
    target.write_text('flask==2.0.0', encoding='utf-8')

    run_dir, results, merged = scan_all(target, dry_run=True, progress_callback=None)

    assert run_dir.parent == tmp_path / 'scan-results'
    assert merged is None
    assert len(results) == 1
    assert results[0].project_kind == 'file'
    assert results[0].status == 'DRYRUN'
