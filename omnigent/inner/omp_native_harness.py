"""``harness: omp-native`` wrap for the native Pi TUI."""

from __future__ import annotations

from fastapi import FastAPI

from omnigent.inner.executor import Executor
from omnigent.inner.omp_native_executor import OmpNativeExecutor
from omnigent.runtime.harnesses._executor_adapter import ExecutorAdapter


def _build_omp_native_executor() -> Executor:
    """
    Construct the native Pi bridge executor.

    :returns: A :class:`OmpNativeExecutor` configured from the harness
        spawn environment.
    """
    return OmpNativeExecutor()


def create_app() -> FastAPI:
    """
    Build the ``omp-native`` harness FastAPI app.

    :returns: The FastAPI app from :class:`ExecutorAdapter`.
    """
    adapter = ExecutorAdapter(executor_factory=_build_omp_native_executor)
    return adapter.build()
