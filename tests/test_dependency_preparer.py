from pathlib import Path

from autoscan.dependency_preparer import discover_prepare_actions, prepare_dependencies
from autoscan.models import CommandRecord, Project


def test_discover_prepare_actions_finds_flutter_missing_lock(monkeypatch, tmp_path):
    project_path = tmp_path / 'app'
    project_path.mkdir()
    (project_path / 'pubspec.yaml').write_text('name: app\n', encoding='utf-8')
    project = Project(project_path, 'app', 'flutter', ['pubspec.yaml'])
    monkeypatch.setattr('autoscan.dependency_preparer.first_existing_tool', lambda names: '/bin/flutter')

    actions = discover_prepare_actions([project])

    assert len(actions) == 1
    assert actions[0].command == ['/bin/flutter', 'pub', 'get']


def test_discover_prepare_actions_skips_when_lock_exists(monkeypatch, tmp_path):
    project_path = tmp_path / 'app'
    project_path.mkdir()
    (project_path / 'pubspec.yaml').write_text('name: app\n', encoding='utf-8')
    (project_path / 'pubspec.lock').write_text('', encoding='utf-8')
    project = Project(project_path, 'app', 'flutter', ['pubspec.yaml'])
    monkeypatch.setattr('autoscan.dependency_preparer.first_existing_tool', lambda names: '/bin/flutter')

    assert discover_prepare_actions([project]) == []


def test_prepare_dependencies_runs_flutter_pub_get(monkeypatch, tmp_path):
    project_path = tmp_path / 'app'
    project_path.mkdir()
    (project_path / 'pubspec.yaml').write_text('name: app\n', encoding='utf-8')
    project = Project(project_path, 'app', 'flutter', ['pubspec.yaml'])
    monkeypatch.setattr('autoscan.dependency_preparer.first_existing_tool', lambda names: '/bin/flutter')

    def fake_run(command, cwd, log_file):
        (cwd / 'pubspec.lock').write_text('packages:\n', encoding='utf-8')
        return CommandRecord(command, str(cwd), 0, 0.1), '', ''

    monkeypatch.setattr('autoscan.dependency_preparer.run_command', fake_run)

    results, records = prepare_dependencies([project], tmp_path / 'prepare.log', enabled=True, assume_yes=True)

    assert results[0].status == 'OK'
    assert records[0].command == ['/bin/flutter', 'pub', 'get']


def test_prepare_dependencies_records_failure(monkeypatch, tmp_path):
    project_path = tmp_path / 'app'
    project_path.mkdir()
    (project_path / 'pubspec.yaml').write_text('name: app\n', encoding='utf-8')
    project = Project(project_path, 'app', 'flutter', ['pubspec.yaml'])
    monkeypatch.setattr('autoscan.dependency_preparer.first_existing_tool', lambda names: '/bin/flutter')
    monkeypatch.setattr('autoscan.dependency_preparer.run_command', lambda command, cwd, log_file: (CommandRecord(command, str(cwd), 1, 0.1), '', 'failed'))

    results, _ = prepare_dependencies([project], tmp_path / 'prepare.log', enabled=True, assume_yes=True)

    assert results[0].status == 'FAIL'
    assert results[0].error == 'Command failed'
