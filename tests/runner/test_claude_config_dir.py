"""Per-agent CLAUDE_CONFIG_DIR for native Claude terminals.

``executor.config.claude_config_dir`` lets catalog agents (e.g.
claude-prof-yo / claude-prof-nana) pin distinct baked credential trees
without flipping the host-wide env.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from omnigent.runner.native.orchestration import (
    ResolvedSpec,
    _claude_config_dir_from_spec,
    _claude_native_terminal_env_for_spec,
)
from omnigent.spec.types import AgentSpec, ExecutorSpec


def _spec(*, claude_config_dir: str | None = None) -> AgentSpec:
    config: dict[str, str] = {"harness": "claude-native"}
    if claude_config_dir is not None:
        config["claude_config_dir"] = claude_config_dir
    return AgentSpec(
        spec_version=1,
        name="claude-prof-yo",
        executor=ExecutorSpec(config=config),
    )


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("/home/agent/claude-accs/.claude-prof-yo", "/home/agent/claude-accs/.claude-prof-yo"),
        ("  /home/agent/claude-accs/.claude-prof-nana  ", "/home/agent/claude-accs/.claude-prof-nana"),
        ("", None),
        ("   ", None),
        (None, None),
    ],
    ids=["yo", "nana-padded", "empty", "whitespace", "missing"],
)
def test_claude_config_dir_from_spec(raw: str | None, expected: str | None) -> None:
    """String config pins are returned stripped; empty/missing → None."""
    if raw is None:
        assert _claude_config_dir_from_spec(_spec()) is None
    else:
        assert _claude_config_dir_from_spec(_spec(claude_config_dir=raw)) == expected


def test_claude_config_dir_from_spec_none_spec() -> None:
    assert _claude_config_dir_from_spec(None) is None


def test_claude_config_dir_from_spec_resolved_wrapper() -> None:
    path = "/home/agent/claude-accs/.claude-prof-nana"
    wrapped = ResolvedSpec(spec=_spec(claude_config_dir=path), workdir=Path("/tmp"))
    assert _claude_config_dir_from_spec(wrapped) == path


def test_claude_native_terminal_env_for_spec_injects_config_dir() -> None:
    """Pinned config dir is merged into the native Claude terminal env."""
    path = "/home/agent/claude-accs/.claude-prof-yo"
    env = _claude_native_terminal_env_for_spec(None, _spec(claude_config_dir=path))
    assert env["CLAUDE_CONFIG_DIR"] == path
    # Tool-search / agent-view defaults from build_native_claude_terminal_env.
    assert len(env) > 1


def test_claude_native_terminal_env_for_spec_without_pin() -> None:
    """No pin → no CLAUDE_CONFIG_DIR key (host/runner env inherits as before)."""
    env = _claude_native_terminal_env_for_spec(None, _spec())
    assert "CLAUDE_CONFIG_DIR" not in env
