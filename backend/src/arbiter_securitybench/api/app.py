"""FastAPI application factory and centralized domain exception mapping."""

from __future__ import annotations

import os

from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from arbiter_securitybench.api.dependencies import AppContainer, build_default_container
from arbiter_securitybench.api.routes import router as v1_router
from arbiter_securitybench.api.schemas import ErrorResponse
from arbiter_securitybench.contracts import (
    PLATFORM_VERSION,
    ConfigurationError,
    DuplicateRegistrationError,
    InvalidLifecycleTransitionError,
    NotFoundError,
    SecurityBenchError,
    StorageError,
    ValidationError,
)

_DEFAULT_CORS_ORIGINS = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:4173",
    "http://127.0.0.1:4173",
]


def _resolve_cors_origins() -> list[str]:
    raw = os.getenv("ASB_CORS_ORIGINS", "").strip()
    if not raw:
        return list(_DEFAULT_CORS_ORIGINS)
    return [origin.strip() for origin in raw.split(",") if origin.strip()]


def _error_response(exc: SecurityBenchError, status_code: int) -> JSONResponse:
    payload = ErrorResponse(
        error_code=exc.error_code,
        category=exc.category.value,
        message=exc.message,
        details=exc.details,
    )
    return JSONResponse(status_code=status_code, content=payload.model_dump(mode="json"))


def create_app(
    container: AppContainer | None = None,
    *,
    database_url: str | None = None,
    load_builtin_datasets: bool | None = None,
) -> FastAPI:
    """Create and configure the FastAPI application instance."""
    app = FastAPI(
        title="Arbiter SecurityBench API",
        version=PLATFORM_VERSION,
        description="Modular AI security benchmarking execution and result query API.",
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=_resolve_cors_origins(),
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.state.container = container or build_default_container(
        database_url=database_url,
        load_builtin_datasets=load_builtin_datasets,
    )

    @app.exception_handler(NotFoundError)
    async def _not_found_handler(_: Request, exc: NotFoundError) -> JSONResponse:
        return _error_response(exc, status.HTTP_404_NOT_FOUND)

    @app.exception_handler(DuplicateRegistrationError)
    async def _duplicate_handler(_: Request, exc: DuplicateRegistrationError) -> JSONResponse:
        return _error_response(exc, status.HTTP_409_CONFLICT)

    @app.exception_handler(ValidationError)
    async def _validation_handler(_: Request, exc: ValidationError) -> JSONResponse:
        return _error_response(exc, status.HTTP_422_UNPROCESSABLE_ENTITY)

    @app.exception_handler(ConfigurationError)
    async def _config_handler(_: Request, exc: ConfigurationError) -> JSONResponse:
        return _error_response(exc, status.HTTP_422_UNPROCESSABLE_ENTITY)

    @app.exception_handler(InvalidLifecycleTransitionError)
    async def _transition_handler(_: Request, exc: InvalidLifecycleTransitionError) -> JSONResponse:
        return _error_response(exc, status.HTTP_422_UNPROCESSABLE_ENTITY)

    @app.exception_handler(StorageError)
    async def _storage_handler(_: Request, exc: StorageError) -> JSONResponse:
        return _error_response(exc, status.HTTP_500_INTERNAL_SERVER_ERROR)

    @app.get("/health", tags=["health"])
    def health() -> dict[str, str]:
        return {"status": "ok", "version": PLATFORM_VERSION}

    app.include_router(v1_router)
    return app
