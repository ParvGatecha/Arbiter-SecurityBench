"""ASGI server entrypoint with Arbiter Security Benchmark v1.0 dataset preloaded."""

from __future__ import annotations

from arbiter_securitybench.api.app import create_app

app = create_app(load_builtin_datasets=True)
