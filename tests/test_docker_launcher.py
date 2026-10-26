"""The Docker prompt delegates to the original CLI without enabling execution."""
import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location('docker_launcher', Path(__file__).parents[1] / 'docker' / 'interactive.py')
launcher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(launcher)


@pytest.fixture
def prompt(monkeypatch):
    monkeypatch.setattr(sys, 'argv', ['interactive.py'])
    calls = []
    def run(args, **kwargs):
        calls.append((args, kwargs))
        return subprocess.CompletedProcess(args, 0)
    monkeypatch.setattr(launcher.subprocess, 'run', run)
    return calls


def input_lines(monkeypatch, *lines):
    replies = iter(lines)
    monkeypatch.setattr('builtins.input', lambda _: next(replies))


def test_prompt_accepts_multiple_packages_and_exits(prompt, monkeypatch):
    input_lines(monkeypatch, '', 'left-pad@1.3.0', '@scope/pkg@1.2.3', 'q')
    assert launcher.main() == 0
    assert [call[0] for call in prompt] == [
        ['malwhunter', 'inspect', 'left-pad@1.3.0', '--no-ai', '--no-detonate', '--format', 'terminal'],
        ['malwhunter', 'inspect', '@scope/pkg@1.2.3', '--no-ai', '--no-detonate', '--format', 'terminal'],
    ]
    assert all(call[1] == {'check': False} for call in prompt)


def test_project_directory_uses_scan(prompt, monkeypatch, tmp_path):
    input_lines(monkeypatch, str(tmp_path), 'exit')
    assert launcher.main() == 0
    assert prompt[0][0][:3] == ['malwhunter', 'scan', str(tmp_path)]


def test_missing_directory_does_not_start_scan(prompt, monkeypatch, tmp_path):
    input_lines(monkeypatch, str(tmp_path / 'missing'), 'quit')
    assert launcher.main() == 0
    assert prompt == []


def test_eof_exits_without_starting_scan(prompt, monkeypatch):
    def closed(_):
        raise EOFError
    monkeypatch.setattr('builtins.input', closed)
    assert launcher.main() == 0
    assert prompt == []


def test_ctrl_c_returns_to_prompt(prompt, monkeypatch):
    replies = iter([KeyboardInterrupt(), 'q'])
    def reply(_):
        value = next(replies)
        if isinstance(value, BaseException):
            raise value
        return value
    monkeypatch.setattr('builtins.input', reply)
    assert launcher.main() == 0
    assert prompt == []


def test_direct_command_preserves_arguments_and_exit_code(monkeypatch):
    args = ['inspect', 'left-pad@1.3.0', '--no-ai', '--no-detonate']
    monkeypatch.setattr(sys, 'argv', ['interactive.py', *args])
    def call(command):
        assert command == ['malwhunter', *args]
        return 2
    monkeypatch.setattr(launcher.subprocess, 'call', call)
    assert launcher.main() == 2
