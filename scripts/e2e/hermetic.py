# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

"""Environment isolation shared by the live-upstream verification scripts."""

import os
from pathlib import Path


def pipelock_environment(workdir: Path, config_path: Path) -> dict[str, str]:
    """Return an environment that cannot discover installed Pipelock state."""
    root = (workdir / "hermetic").resolve()
    paths = {
        "HOME": root / "home",
        "XDG_CONFIG_HOME": root / "config",
        "XDG_DATA_HOME": root / "data",
        "XDG_STATE_HOME": root / "state",
        "XDG_CACHE_HOME": root / "cache",
    }
    for path in paths.values():
        path.mkdir(parents=True, exist_ok=True, mode=0o700)

    posture_dir = root / "posture"
    posture_dir.mkdir(parents=True, exist_ok=True, mode=0o700)

    env = os.environ.copy()
    env.update({name: str(path) for name, path in paths.items()})
    env["PIPELOCK_CONFIG"] = str(config_path.resolve())
    env["PIPELOCK_POSTURE_PROOF"] = str(posture_dir / "absent-proof.json")
    return env
