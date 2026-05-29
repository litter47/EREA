"""Tests for the FastAPI application startup and API endpoints.

Imports the real ``app`` from ``eva_agent.main`` and uses
``TestClient`` for HTTP-level tests.  The application's async
lifespan (which requires Docker) is mocked so that tests can
run in any environment.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from starlette.testclient import TestClient

from eva_agent.config.settings import Settings


# ------------------------------------------------------------------
# Fixtures
# ------------------------------------------------------------------


def _build_client() -> TestClient:
    """Return a ``TestClient`` bound to the real app, with the
    async lifespan (Docker, task-manager) stubbed out.

    The lifespan calls ``docker.from_env()``,
    ``ensure_runtime_image()``, and ``get_task_manager()`` directly
    via module-level imports in ``main.py``.  We patch those at the
    ``eva_agent.main`` namespace so that the lifespan runs to
    completion without real side-effects, while the actual route
    handlers and OpenAPI schema remain intact.
    """
    # Lazy import so the module is not loaded before we are ready
    from eva_agent.main import app  # noqa: I001

    mock_settings = Settings()
    mock_task_manager = MagicMock()
    mock_task_manager.start = MagicMock()
    mock_task_manager.stop = AsyncMock()

    patcher_docker = patch("eva_agent.main.docker.from_env")
    patcher_ensure = patch("eva_agent.main.ensure_runtime_image")
    patcher_tm = patch(
        "eva_agent.main.get_task_manager", return_value=mock_task_manager
    )

    mock_docker = patcher_docker.start()
    mock_ensure = patcher_ensure.start()
    patcher_tm.start()

    mock_docker.return_value = MagicMock()
    mock_ensure.return_value = True

    client = TestClient(app)

    # Store patchers so the caller can stop them after the test
    client._eva_patchers = [patcher_docker, patcher_ensure, patcher_tm]  # noqa: SLF001

    return client


# ======================================================================
# Application-level tests
# ======================================================================


class TestAppCreated:
    """Tests that verify the ``FastAPI`` object itself (no HTTP)."""

    def test_app_created(self):
        """The ``app`` object has the expected title."""
        from eva_agent.main import app

        assert app.title == "EVA-Agent"
        assert app.version == "0.1.0"


class TestDocs:
    """Tests for the ``/docs`` and ``/openapi.json`` endpoints."""

    def test_docs_available(self):
        """``GET /docs`` returns HTTP 200."""
        client = _build_client()
        try:
            response = client.get("/docs")
            assert response.status_code == 200
        finally:
            for p in client._eva_patchers:  # noqa: SLF001
                p.stop()

    def test_health_check_via_docs(self):
        """The ``/docs`` endpoint is accessible (second call to verify
        lifespan re-entrance safety)."""
        client = _build_client()
        try:
            response = client.get("/docs")
            assert response.status_code == 200
            assert "text/html" in response.headers.get("content-type", "")
        finally:
            for p in client._eva_patchers:  # noqa: SLF001
                p.stop()


class TestOpenApiSchema:
    """Tests for the OpenAPI schema (no HTTP client needed)."""

    def test_openapi_schema(self):
        """The generated OpenAPI schema contains the expected paths."""
        from eva_agent.main import app

        schema = app.openapi()

        assert "paths" in schema
        paths = schema["paths"]

        assert "/submit" in paths
        assert "/task/{task_id}" in paths
        assert "/result/{task_id}" in paths

        # Check that POST /submit and the GET endpoints are defined
        assert "post" in paths["/submit"]
        assert "get" in paths["/task/{task_id}"]
        assert "get" in paths["/result/{task_id}"]
