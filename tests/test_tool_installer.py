from autoscan.models import Project, ScanResult
from autoscan.tool_installer import (
    ToolRequirement,
    detect_missing_tools,
    install_command,
    install_missing_tools,
    missing_tools_from_results,
)


def test_detect_missing_tools_requires_trivy(monkeypatch, tmp_path):
    monkeypatch.setattr('autoscan.tool_installer.shutil.which', lambda name: None)
    project = Project(path=tmp_path, name='app', kind='node', markers=['package.json'])

    missing = detect_missing_tools([project], trivy_only=False, maven_prebuild=True, dry_run=False)

    assert [item.tool for item in missing] == ['trivy', 'node']
    assert missing[0].required is True


def test_detect_missing_tools_ignores_dry_run(monkeypatch, tmp_path):
    monkeypatch.setattr('autoscan.tool_installer.shutil.which', lambda name: None)
    project = Project(path=tmp_path, name='app', kind='maven', markers=['pom.xml'])

    assert detect_missing_tools([project], trivy_only=False, maven_prebuild=True, dry_run=True) == []


def test_missing_tools_from_failed_results():
    result = ScanResult(name='svc', project_path='.', project_kind='unknown', output_dir='.')
    result.errors.append('trivy not found in PATH')

    assert missing_tools_from_results([result]) == ['trivy']


def test_install_missing_tools_respects_decline(monkeypatch):
    monkeypatch.setattr('autoscan.tool_installer.supported_package_manager', lambda: 'brew')

    called = False
    def fake_run(command, check=False):
        nonlocal called
        called = True

    monkeypatch.setattr('autoscan.tool_installer.subprocess.run', fake_run)

    ok = install_missing_tools(
        [ToolRequirement('trivy', 'trivy', 'required', True)],
        prompt=lambda message: 'n',
    )

    assert ok is False
    assert called is False


def test_install_command_brew_cask():
    assert install_command('brew', '--cask flutter') == ['brew', 'install', '--cask', 'flutter']
