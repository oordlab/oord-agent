# tests/agent/test_agent_entrypoint.py
import os
import subprocess
import sys
from pathlib import Path

import pytest


def test_agent_entrypoint_sender(tmp_path):
    cfg = tmp_path / "sender.toml"
    cfg.write_text(
        """
        mode = "sender"
        [core]
        base_url = "http://core"
        [org]
        id = "ORG"
        [agent]
        poll_interval_sec = 1
        settle_seconds = 0
        [logging]
        level = "INFO"
        [sender.paths]
        watch_dir = "%s/watch"
        out_dir = "%s/out"
        state_file = "%s/state.json"
        """ % (tmp_path, tmp_path, tmp_path)
    )

    (tmp_path / "watch").mkdir()
    (tmp_path / "out").mkdir()

    # Run entrypoint in one-shot mode by adding a ready folder.
    batch = tmp_path / "watch" / "b1"
    batch.mkdir()

    # Env: keep PATH, add PYTHONPATH=.
    env = {**os.environ, "PYTHONPATH": "."}

    # Sanity: just assert process starts and logs agent_start
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "cli.oord_cli",
            "agent",
            "--config",
            str(cfg),
            "--once",
        ],
        capture_output=True,
        text=True,
        env=env,
        timeout=10,
    )


    assert proc.returncode == 0
    assert "event=agent_entrypoint" in proc.stdout or proc.stderr
