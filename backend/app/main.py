"""
FastAPI main application.
"""
from __future__ import annotations

import logging
import time
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.config import get_settings
from app.utils.logging_config import setup_logging

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown lifecycle."""
    settings = get_settings()
    setup_logging(settings.LOG_LEVEL, settings.LOG_FILE)
    logger.info("PhishShield backend starting up...")

    # Ensure data directories exist
    for d in ["data", "models", "reports", "logs", "uploads"]:
        Path(d).mkdir(parents=True, exist_ok=True)

    # Initialise DB (also imports user model so it gets created)
    from app.database import user_model  # noqa: F401
    from app.database.connection import init_db
    init_db()
    logger.info("Database initialised")

    # Initialise case tables
    try:
        from app.cases.store import init_case_tables
        init_case_tables()
        logger.info("Case tables initialised")
    except Exception as e:
        logger.error(f"Failed to initialise case tables: {e}")

    # Pre-load model (non-blocking; log result)
    from app.services.model_loader import try_load_model
    model, err = try_load_model()
    if model:
        logger.info(f"URL model loaded: {model.model_version}")
    else:
        logger.warning(f"URL model not loaded: {err}")

    # Pre-load reference data
    try:
        from app.security.domain_checks import load_brand_domains, load_tunnel_hosts
        brands = load_brand_domains()
        tunnels = load_tunnel_hosts()
        logger.info(f"Loaded {len(brands)} brands, {len(tunnels)} tunnel hosts")
    except Exception as e:
        logger.error(f"Reference data load error: {e}")

    yield

    logger.info("PhishShield backend shutting down.")


def create_app() -> FastAPI:
    settings = get_settings()

    app = FastAPI(
        title="PhishShield API",
        version="1.0.0",
        description="Phishing, scam and digital-evidence investigation API",
        docs_url="/api/docs" if settings.is_development else None,
        redoc_url="/api/redoc" if settings.is_development else None,
        lifespan=lifespan,
    )

    # CORS
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[settings.FRONTEND_ORIGIN],
        allow_credentials=True,
        allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
        allow_headers=["*"],
    )

    # Request timing middleware
    @app.middleware("http")
    async def add_timing_header(request: Request, call_next):
        start = time.perf_counter()
        response = await call_next(request)
        duration = time.perf_counter() - start
        response.headers["X-Process-Time"] = f"{duration:.3f}s"
        return response

    # Security headers
    @app.middleware("http")
    async def add_security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        return response

    # Error handlers
    @app.exception_handler(Exception)
    async def global_exception_handler(request: Request, exc: Exception):
        logger.error(f"Unhandled error on {request.url.path}: {type(exc).__name__}: {exc}")
        return JSONResponse(
            status_code=500,
            content={"error": {"code": "INTERNAL_ERROR", "message": "An internal error occurred."}},
        )

    # Register routers
    from app.api.health import router as health_router
    from app.api.url_routes import router as url_router
    from app.api.apk_routes import router as apk_router
    from app.api.sms_routes import router as sms_router
    from app.api.screenshot_routes import router as screenshot_router
    from app.api.history_routes import router as history_router
    from app.api.auth_routes import router as auth_router
    from app.api.case_routes import router as case_router

    app.include_router(health_router, prefix="/api")
    app.include_router(auth_router, prefix="/api")
    app.include_router(case_router, prefix="/api")
    app.include_router(url_router, prefix="/api/url")
    app.include_router(apk_router, prefix="/api/apk")
    app.include_router(sms_router, prefix="/api/sms")
    app.include_router(screenshot_router, prefix="/api/screenshot")
    app.include_router(history_router, prefix="/api")

    return app


app = create_app()
