"""Administrative API endpoints for GDPR log management."""

from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from src.core.logging.gdpr import GDPRLogManager
from src.core.logging.retention import LogRetentionManager, get_log_directory_stats

router = APIRouter(prefix="/admin/gdpr", tags=["GDPR Administration"])

# TODO: Add proper authentication/authorization middleware
# For now, this is a basic implementation


class UserErasureRequest(BaseModel):
    """Request model for user data erasure."""
    user_id: str
    requester_id: str
    backup_before_deletion: bool = True


class UserExportRequest(BaseModel):
    """Request model for user data export."""
    user_id: str
    requester_id: str


class LogCleanupRequest(BaseModel):
    """Request model for manual log cleanup."""
    retention_days: int = 90
    dry_run: bool = True


def get_log_directory() -> Path:
    """Get the configured log directory."""
    # TODO: Get this from settings
    return Path("/var/log/app")


def get_gdpr_manager() -> GDPRLogManager:
    """Get GDPR log manager instance."""
    return GDPRLogManager(get_log_directory())


def get_retention_manager() -> LogRetentionManager:
    """Get log retention manager instance."""
    return LogRetentionManager()


@router.post("/erase-user-data")
async def erase_user_data(
    request: UserErasureRequest,
    gdpr_manager: GDPRLogManager = Depends(get_gdpr_manager)
) -> dict[str, Any]:
    """
    Erase all data for a specific user (GDPR Article 17 - Right to erasure).

    This endpoint removes all log entries containing the specified user's data
    and creates a backup if requested.
    """
    try:
        result = gdpr_manager.erase_user_data(
            user_id=request.user_id,
            requester_id=request.requester_id,
            backup_before_deletion=request.backup_before_deletion
        )
        return {
            "status": "success",
            "message": f"User data erasure completed for user {request.user_id}",
            "details": result
        }
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to erase user data: {str(e)}"
        ) from e


@router.post("/export-user-data")
async def export_user_data(
    request: UserExportRequest,
    gdpr_manager: GDPRLogManager = Depends(get_gdpr_manager)
) -> dict[str, Any]:
    """
    Export all data for a specific user (GDPR Article 20 - Right to data portability).

    This endpoint extracts all log entries for the specified user and creates
    an export file for download.
    """
    try:
        result = gdpr_manager.export_user_data(
            user_id=request.user_id,
            requester_id=request.requester_id
        )
        return {
            "status": "success",
            "message": f"User data export completed for user {request.user_id}",
            "export_data": result
        }
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to export user data: {str(e)}"
        ) from e


@router.get("/search-user/{identifier}")
async def search_user_references(
    identifier: str,
    gdpr_manager: GDPRLogManager = Depends(get_gdpr_manager)
) -> dict[str, Any]:
    """
    Search for references to a user identifier in logs.

    This helps identify all places where user data might exist before
    performing erasure operations.
    """
    try:
        result = gdpr_manager.search_user_references(identifier)
        return {
            "status": "success",
            "search_results": result
        }
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to search user references: {str(e)}"
        ) from e


@router.post("/cleanup-logs")
async def manual_log_cleanup(
    request: LogCleanupRequest,
    retention_manager: LogRetentionManager = Depends(get_retention_manager)
) -> dict[str, Any]:
    """
    Manually trigger log cleanup based on retention policy.

    This allows administrators to test cleanup policies or perform
    manual cleanup when needed.
    """
    try:
        retention_manager.retention_days = request.retention_days
        retention_manager.dry_run = request.dry_run

        result = await retention_manager.cleanup_old_logs(get_log_directory())

        return {
            "status": "success",
            "message": "Log cleanup completed",
            "cleanup_stats": result
        }
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to cleanup logs: {str(e)}"
        ) from e


@router.get("/log-statistics")
async def get_log_statistics() -> dict[str, Any]:
    """
    Get statistics about the current log directory.

    This provides information about log file sizes, counts, and retention status.
    """
    try:
        log_dir = get_log_directory()
        stats = get_log_directory_stats(log_dir)

        return {
            "status": "success",
            "statistics": stats
        }
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to get log statistics: {str(e)}"
        ) from e


@router.get("/compliance-status")
async def get_compliance_status() -> dict[str, Any]:
    """
    Get current GDPR compliance status.

    This endpoint provides an overview of compliance features and their status.
    """
    from src.core.logging.config import LogConfig

    try:
        config = LogConfig()
        log_dir = get_log_directory()
        stats = get_log_directory_stats(log_dir)

        compliance_status = {
            "pii_filtering_enabled": config.enable_pii_filtering,
            "log_retention_days": config.log_retention_days,
            "tamper_protection_enabled": config.enable_tamper_protection,
            "log_directory": str(log_dir),
            "log_directory_exists": log_dir.exists(),
            "current_log_stats": stats,
            "compliance_features": {
                "right_to_erasure": "available",
                "data_portability": "available",
                "automatic_retention": "active",
                "audit_logging": "active",
                "pii_redaction": "active" if config.enable_pii_filtering else "disabled"
            }
        }

        # Calculate compliance score
        score = 0
        if config.enable_pii_filtering:
            score += 25
        if config.log_retention_days <= 90:
            score += 25
        if config.enable_tamper_protection:
            score += 25
        if log_dir.exists():
            score += 25

        compliance_status["compliance_score"] = f"{score}/100"
        compliance_status["compliance_level"] = (
            "Excellent" if score >= 90 else
            "Good" if score >= 75 else
            "Needs Improvement" if score >= 50 else
            "Critical Issues"
        )

        return {
            "status": "success",
            "compliance_status": compliance_status
        }
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to get compliance status: {str(e)}"
        ) from e
