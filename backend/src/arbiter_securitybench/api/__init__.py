"""FastAPI REST API transport boundary."""

from arbiter_securitybench.api.app import create_app
from arbiter_securitybench.api.dependencies import AppContainer, build_default_container

__all__ = ["AppContainer", "build_default_container", "create_app"]
