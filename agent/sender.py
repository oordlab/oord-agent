# agent/sender.py
from __future__ import annotations

import datetime
import json
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Tuple

from .config import AgentConfig

def _log(msg: str) -> None:
    """
    Minimal human-readable logging for sender events.
    """
    ts = datetime.datetime.utcnow().isoformat(timespec="seconds") + "Z"
    print(f"[sender] {ts} {msg}")


@dataclass
class SenderState:
    processed_batches: Dict[str, str]


def load_state(path: Path) -> SenderState:
    if not path.is_file():
        return SenderState(processed_batches={})
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return SenderState(processed_batches={})
    processed = data.get("processed_batches") or {}
    if not isinstance(processed, dict):
        processed = {}
    # normalize keys to str
    processed_str: Dict[str, str] = {}
    for k, v in processed.items():
        if isinstance(k, str) and isinstance(v, str):
            processed_str[k] = v
    return SenderState(processed_batches=processed_str)


def save_state(path: Path, state: SenderState) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    data = {"processed_batches": state.processed_batches}
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, sort_keys=True, indent=2), encoding="utf-8")
    tmp.replace(path)


def _latest_mtime(p: Path) -> float:
    latest = p.stat().st_mtime
    for child in p.rglob("*"):
        try:
            st = child.stat()
        except FileNotFoundError:
            continue
        if st.st_mtime > latest:
            latest = st.st_mtime
    return latest


def is_folder_stable(folder: Path, settle_seconds: int, now: float | None = None) -> bool:
    if now is None:
        now = time.time()
    latest = _latest_mtime(folder)
    return (now - latest) >= settle_seconds


def find_ready_batches(
    watch_dir: Path,
    state: SenderState,
    settle_seconds: int,
    now: float | None = None,
) -> List[Path]:
    """
    One batch = one immediate subfolder of watch_dir.

    Returns a list of batch directories that:
      - are not marked 'sealed' in state
      - have not changed in the last settle_seconds
    """
    ready: List[Path] = []
    processed = state.processed_batches
    if not watch_dir.is_dir():
        return ready

    for child in sorted(watch_dir.iterdir()):
        if not child.is_dir():
            continue
        name = child.name
        if processed.get(name) == "sealed":
            continue
        if not is_folder_stable(child, settle_seconds=settle_seconds, now=now):
            continue
        ready.append(child)
    return ready


def _compute_batch_id(batch_dir: Path, prefix: str | None) -> str:
    name = batch_dir.name
    if prefix:
        return f"{prefix}-{name}"
    return name


def seal_batch_via_cli(
    cfg: AgentConfig,
    batch_dir: Path,
    out_dir: Path,
) -> Tuple[int, str, str]:
    """
    Call the Oord CLI as a subprocess to seal a batch directory.

    Returns: (exit_code, stdout, stderr)
    """
    batch_id = _compute_batch_id(batch_dir, cfg.org.batch_prefix)
    
    _log(f"sealing batch name={batch_dir.name} batch_id={batch_id} input_dir={batch_dir} out_dir={out_dir}")

    cmd = [
        sys.executable,
        "-m",
        "cli.oord_cli",
        "seal",
        "--input-dir",
        str(batch_dir),
        "--out",
        str(out_dir),
        "--core-url",
        cfg.core.base_url,
        "--org-id",
        cfg.org.id,
        "--batch-id",
        batch_id,
    ]
    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
    )
    return proc.returncode, proc.stdout, proc.stderr


def run_sender_loop(cfg: AgentConfig, once: bool = False) -> None:
    if cfg.sender_paths is None:
        raise RuntimeError("sender mode requires sender_paths in config")

    watch_dir = cfg.sender_paths.watch_dir
    out_dir = cfg.sender_paths.out_dir
    state_path = cfg.sender_paths.state_file

    _log(f"starting sender loop watch_dir={watch_dir} out_dir={out_dir} state_file={state_path}")

    state = load_state(state_path)

    while True:
        now = time.time()
        ready_batches = find_ready_batches(
            watch_dir=watch_dir,
            state=state,
            settle_seconds=cfg.agent.settle_seconds,
            now=now,
        )

        if ready_batches:
            _log(f"found {len(ready_batches)} ready batch(es)")

        for batch_dir in ready_batches:
            code, stdout, stderr = seal_batch_via_cli(cfg, batch_dir, out_dir)
            if stdout:
                # passthrough CLI stdout for now
                print(stdout.strip())
            if stderr:
                # passthrough CLI stderr for now
                print(stderr.strip(), file=sys.stderr)

            name = batch_dir.name
            if code == 0:
                _log(f"seal succeeded for batch name={name}")
                state.processed_batches[name] = "sealed"
                save_state(state_path, state)
            else:
                # treat non-zero exit as env/usage error: do NOT mark processed
                # so the batch remains eligible for retry once the environment is fixed
                _log(f"seal failed for batch name={name} exit_code={code}; leaving state unchanged for retry")


        if once:
            # Dev/one-shot mode: process whatever was ready and exit.
            break

        time.sleep(cfg.agent.poll_interval_sec)

