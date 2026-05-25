"""Runtime infrastructure for the Decepticon orchestrator process.

Currently exposes the graceful shutdown installer; future runtime
primitives (event log, resume) will live here as well.
"""

from decepticon.runtime.shutdown import (
    LangGraphState,
    install_shutdown_handlers,
)

__all__ = [
    "LangGraphState",
    "install_shutdown_handlers",
]
