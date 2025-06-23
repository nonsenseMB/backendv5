from contextlib import asynccontextmanager
import time
import uuid

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware

from src.api.admin import router as admin_router
from src.core.config import settings
from src.core.logging.config import configure_logging, get_logger
from src.core.context import set_request_context, clear_request_context, RequestContext
from src.core.logging.audit import log_audit_event, AuditEventType, AuditSeverity

# Initialize logging system
configure_logging()
logger = get_logger(__name__)
logger.info("Starting Backend v5...")


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    print(f"Starting {settings.APP_NAME} v{settings.APP_VERSION}")

    # Start background log cleanup for GDPR compliance
    import asyncio
    from pathlib import Path

    from src.core.logging.retention import schedule_cleanup

    log_directory = Path("/var/log/app").resolve()
    log_directory.mkdir(parents=True, exist_ok=True)

    # Start cleanup task in background (non-blocking)
    cleanup_task = asyncio.create_task(
        schedule_cleanup(
            log_directory=log_directory,
            retention_days=90,  # GDPR compliance: 90 days retention
            check_interval_hours=24  # Check daily
        )
    )

    logger.info("🗂️  Started automatic log cleanup for GDPR compliance",
                retention_days=90, log_directory=str(log_directory))

    # Log application startup
    log_audit_event(
        event_type=AuditEventType.SYSTEM_START,
        severity=AuditSeverity.LOW,
        details={
            "app_name": settings.APP_NAME,
            "version": settings.APP_VERSION,
            "environment": getattr(settings, 'ENVIRONMENT', 'development')
        }
    )

    yield

    # Shutdown
    print("Shutting down...")
    
    # Log application shutdown
    log_audit_event(
        event_type=AuditEventType.SYSTEM_STOP,
        severity=AuditSeverity.LOW,
        details={
            "app_name": settings.APP_NAME,
            "version": settings.APP_VERSION
        }
    )
    
    cleanup_task.cancel()
    try:
        await cleanup_task
    except asyncio.CancelledError:
        logger.info("🛑 Log cleanup task cancelled")


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    lifespan=lifespan,
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=[str(origin) for origin in settings.CORS_ORIGINS],
    allow_credentials=settings.CORS_ALLOW_CREDENTIALS,
    allow_methods=settings.CORS_ALLOW_METHODS,
    allow_headers=settings.CORS_ALLOW_HEADERS,
)

# Logging middleware - MUST be added first to catch all requests
@app.middleware("http")
async def logging_middleware(request: Request, call_next):
    """Add request context and log all requests/responses."""
    start_time = time.time()
    
    # Generate or extract request ID
    request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))
    
    # Set request context for all logs in this request
    context = RequestContext(
        request_id=request_id,
        tenant_id=request.headers.get("X-Tenant-ID"),
        user_id=getattr(request.state, "user_id", None) if hasattr(request.state, "user_id") else None,
        session_id=request.headers.get("X-Session-ID"),
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("User-Agent")
    )
    set_request_context(context)
    
    # Log request
    logger.info(
        "Request started",
        method=request.method,
        path=request.url.path,
        query_params=dict(request.query_params) if request.query_params else None
    )
    
    try:
        # Process request
        response = await call_next(request)
        
        # Calculate duration
        duration_ms = (time.time() - start_time) * 1000
        
        # Log response
        logger.info(
            "Request completed",
            method=request.method,
            path=request.url.path,
            status_code=response.status_code,
            duration_ms=round(duration_ms, 2)
        )
        
        # Add request ID to response headers
        response.headers["X-Request-ID"] = request_id
        
        return response
        
    except Exception as e:
        duration_ms = (time.time() - start_time) * 1000
        
        # Log error
        logger.error(
            "Request failed",
            method=request.method,
            path=request.url.path,
            error=str(e),
            duration_ms=round(duration_ms, 2),
            exc_info=True
        )
        raise
    finally:
        # Clear context
        clear_request_context()

# Include admin API for GDPR management
app.include_router(admin_router)


@app.get("/")
async def root():
    return {"name": settings.APP_NAME, "version": settings.APP_VERSION, "status": "running"}


@app.get("/health")
async def health():
    """Comprehensive health check endpoint with system status."""
    import os
    from datetime import datetime
    from pathlib import Path

    import psutil

    # Basic health status
    health_status = {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "application": {
            "name": settings.APP_NAME,
            "version": settings.APP_VERSION,
            "environment": os.getenv("ENVIRONMENT", "development")
        }
    }

    try:
        # System metrics
        health_status["system"] = {
            "cpu_percent": psutil.cpu_percent(interval=1),
            "memory": {
                "total_mb": round(psutil.virtual_memory().total / 1024 / 1024, 2),
                "available_mb": round(psutil.virtual_memory().available / 1024 / 1024, 2),
                "percent_used": psutil.virtual_memory().percent
            },
            "disk": {
                "total_gb": round(psutil.disk_usage('/').total / 1024 / 1024 / 1024, 2),
                "free_gb": round(psutil.disk_usage('/').free / 1024 / 1024 / 1024, 2),
                "percent_used": psutil.disk_usage('/').percent
            }
        }

        # GDPR Compliance Status
        from src.core.logging.config import LogConfig
        config = LogConfig()

        health_status["gdpr_compliance"] = {
            "pii_filtering_enabled": config.enable_pii_filtering,
            "log_retention_days": config.log_retention_days,
            "tamper_protection": config.enable_tamper_protection,
            "status": "compliant" if config.enable_pii_filtering else "non_compliant"
        }

        # Log Directory Status
        log_dir = Path("/var/log/app")
        if log_dir.exists():
            from src.core.logging.retention import get_log_directory_stats
            log_stats = get_log_directory_stats(log_dir)
            health_status["logging"] = {
                "log_directory_exists": True,
                "log_files_count": log_stats.get("file_count", 0),
                "total_log_size_mb": log_stats.get("total_size_mb", 0),
                "oldest_log": log_stats.get("oldest_file"),
                "newest_log": log_stats.get("newest_file")
            }
        else:
            health_status["logging"] = {
                "log_directory_exists": False,
                "status": "warning",
                "message": "Log directory not found"
            }

        # Database connectivity (placeholder - adjust for your DB)
        health_status["database"] = {
            "status": "not_configured",
            "message": "Database health check not implemented"
        }

        # Redis connectivity (placeholder - adjust for your Redis)
        health_status["redis"] = {
            "status": "not_configured",
            "message": "Redis health check not implemented"
        }

        # Overall health assessment
        warnings = []
        if not config.enable_pii_filtering:
            warnings.append("PII filtering disabled - GDPR compliance risk")
        if not log_dir.exists():
            warnings.append("Log directory missing")

        if warnings:
            health_status["status"] = "degraded"
            health_status["warnings"] = warnings

    except Exception as e:
        health_status["status"] = "unhealthy"
        health_status["error"] = str(e)
        logger.error("Health check failed", error=str(e))

    return health_status


@app.get("/health/simple")
async def health_simple():
    """Simple health check for load balancers (fast response)."""
    from datetime import datetime
    return {"status": "ok", "timestamp": datetime.utcnow().isoformat()}
