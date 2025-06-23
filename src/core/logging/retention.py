"""Log retention management for GDPR compliance.

This module provides automatic cleanup of old log files to ensure
compliance with data retention policies.
"""

import asyncio
from datetime import datetime, timedelta
from pathlib import Path

import structlog

from .audit import AuditEventType, AuditSeverity, log_audit_event

logger = structlog.get_logger(__name__)


class LogRetentionManager:
    """Manages automatic cleanup of old log files for GDPR compliance."""

    def __init__(self, retention_days: int = 90, dry_run: bool = False):
        """Initialize the retention manager.

        Args:
            retention_days: Number of days to retain logs
            dry_run: If True, only simulate deletions without actually deleting
        """
        self.retention_days = retention_days
        self.dry_run = dry_run
        self.deleted_files: list[Path] = []
        self.freed_space: int = 0

    async def cleanup_old_logs(self, log_directory: Path) -> dict:
        """Clean up old log files based on retention policy.

        Args:
            log_directory: Directory containing log files

        Returns:
            Dictionary with cleanup statistics
        """
        if not log_directory.exists():
            logger.warning("Log directory does not exist", directory=str(log_directory))
            return {"error": "Directory not found"}

        cutoff_date = datetime.now() - timedelta(days=self.retention_days)
        logger.info(
            "Starting log cleanup",
            retention_days=self.retention_days,
            cutoff_date=cutoff_date.isoformat(),
            directory=str(log_directory),
            dry_run=self.dry_run
        )

        # Find old log files
        old_files = self._find_old_files(log_directory, cutoff_date)

        if not old_files:
            logger.info("No old log files found for cleanup")
            return {
                "deleted_files": 0,
                "freed_space_mb": 0,
                "retention_days": self.retention_days
            }

        # Delete old files
        stats = await self._delete_files(old_files)

        # Log audit event
        log_audit_event(
            event_type=AuditEventType.DATA_ERASURE_REQUEST,
            user_id="system",
            details={
                "retention_cleanup": True,
                "files_deleted": len(self.deleted_files),
                "freed_space_mb": round(self.freed_space / 1024 / 1024, 2),
                "cutoff_date": cutoff_date.isoformat(),
                "dry_run": self.dry_run
            },
            severity=AuditSeverity.MEDIUM
        )

        return stats

    def _find_old_files(self, log_directory: Path, cutoff_date: datetime) -> list[Path]:
        """Find log files older than the cutoff date."""
        old_files = []

        # Common log file patterns
        patterns = ["*.log", "*.log.*", "*.json", "*.audit"]

        for pattern in patterns:
            for file_path in log_directory.glob(pattern):
                if file_path.is_file():
                    # Check file modification time
                    file_mtime = datetime.fromtimestamp(file_path.stat().st_mtime)
                    if file_mtime < cutoff_date:
                        old_files.append(file_path)
                        logger.debug(
                            "Found old log file",
                            file=str(file_path),
                            file_date=file_mtime.isoformat(),
                            size_mb=round(file_path.stat().st_size / 1024 / 1024, 2)
                        )

        # Sort by modification time (oldest first)
        old_files.sort(key=lambda f: f.stat().st_mtime)

        logger.info(f"Found {len(old_files)} old log files for cleanup")
        return old_files

    async def _delete_files(self, files: list[Path]) -> dict:
        """Delete the specified files."""
        deleted_count = 0
        total_size = 0
        errors = []

        for file_path in files:
            try:
                file_size = file_path.stat().st_size

                if self.dry_run:
                    logger.info(
                        "DRY RUN: Would delete log file",
                        file=str(file_path),
                        size_mb=round(file_size / 1024 / 1024, 2)
                    )
                else:
                    # Actually delete the file
                    file_path.unlink()
                    logger.info(
                        "Deleted old log file",
                        file=str(file_path),
                        size_mb=round(file_size / 1024 / 1024, 2)
                    )

                self.deleted_files.append(file_path)
                total_size += file_size
                deleted_count += 1

            except Exception as e:
                error_msg = f"Failed to delete {file_path}: {e}"
                logger.error("File deletion failed", file=str(file_path), error=str(e))
                errors.append(error_msg)

        self.freed_space = total_size

        return {
            "deleted_files": deleted_count,
            "freed_space_mb": round(total_size / 1024 / 1024, 2),
            "retention_days": self.retention_days,
            "errors": errors,
            "dry_run": self.dry_run
        }

    async def cleanup_by_size(self, log_directory: Path, max_size_mb: int) -> dict:
        """Clean up logs when directory exceeds size limit.

        Args:
            log_directory: Directory containing log files
            max_size_mb: Maximum directory size in MB

        Returns:
            Dictionary with cleanup statistics
        """
        if not log_directory.exists():
            return {"error": "Directory not found"}

        # Calculate current directory size
        total_size = sum(
            f.stat().st_size for f in log_directory.rglob("*") if f.is_file()
        )
        current_size_mb = total_size / 1024 / 1024

        if current_size_mb <= max_size_mb:
            logger.info(
                "Directory size within limits",
                current_size_mb=round(current_size_mb, 2),
                max_size_mb=max_size_mb
            )
            return {
                "current_size_mb": round(current_size_mb, 2),
                "max_size_mb": max_size_mb,
                "cleanup_needed": False
            }

        # Find files to delete (oldest first)
        all_files = []
        for pattern in ["*.log", "*.log.*", "*.json", "*.audit"]:
            all_files.extend(log_directory.glob(pattern))

        # Sort by modification time (oldest first)
        all_files.sort(key=lambda f: f.stat().st_mtime)

        # Delete files until we're under the size limit
        deleted_size = 0
        target_to_delete = (current_size_mb - max_size_mb) * 1024 * 1024

        files_to_delete = []
        for file_path in all_files:
            if deleted_size >= target_to_delete:
                break
            file_size = file_path.stat().st_size
            files_to_delete.append(file_path)
            deleted_size += file_size

        # Perform deletion
        stats = await self._delete_files(files_to_delete)
        stats.update({
            "cleanup_reason": "size_limit",
            "original_size_mb": round(current_size_mb, 2),
            "max_size_mb": max_size_mb
        })

        logger.info(
            "Completed size-based cleanup",
            original_size_mb=round(current_size_mb, 2),
            freed_space_mb=stats["freed_space_mb"],
            files_deleted=stats["deleted_files"]
        )

        return stats


async def schedule_cleanup(
    log_directory: Path,
    retention_days: int = 90,
    check_interval_hours: int = 24
) -> None:
    """Schedule periodic log cleanup.

    Args:
        log_directory: Directory containing log files
        retention_days: Number of days to retain logs
        check_interval_hours: How often to check for cleanup (in hours)
    """
    retention_manager = LogRetentionManager(retention_days=retention_days)

    logger.info(
        "Starting scheduled log cleanup",
        retention_days=retention_days,
        check_interval_hours=check_interval_hours,
        directory=str(log_directory)
    )

    while True:
        try:
            await retention_manager.cleanup_old_logs(log_directory)

            # Wait for next cleanup cycle
            await asyncio.sleep(check_interval_hours * 3600)

        except Exception as e:
            logger.error(
                "Error in scheduled cleanup",
                error=str(e),
                retry_in_minutes=60
            )
            # Wait 1 hour before retrying on error
            await asyncio.sleep(3600)


def get_log_directory_stats(log_directory: Path) -> dict:
    """Get statistics about the log directory.

    Returns:
        Dictionary with directory statistics
    """
    if not log_directory.exists():
        return {"error": "Directory not found"}

    total_size = 0
    file_count = 0
    oldest_file = None
    newest_file = None

    for file_path in log_directory.rglob("*"):
        if file_path.is_file() and any(file_path.match(p) for p in ["*.log", "*.log.*", "*.json", "*.audit"]):
            file_count += 1
            file_size = file_path.stat().st_size
            total_size += file_size

            file_mtime = datetime.fromtimestamp(file_path.stat().st_mtime)
            if oldest_file is None or file_mtime < oldest_file:
                oldest_file = file_mtime
            if newest_file is None or file_mtime > newest_file:
                newest_file = file_mtime

    return {
        "total_size_mb": round(total_size / 1024 / 1024, 2),
        "file_count": file_count,
        "oldest_file": oldest_file.isoformat() if oldest_file else None,
        "newest_file": newest_file.isoformat() if newest_file else None,
        "directory": str(log_directory)
    }
