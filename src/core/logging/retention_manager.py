"""
Audit log retention manager for automated cleanup and policy enforcement.
Handles retention policy application, log archival, and compliance-driven cleanup.
"""

import asyncio
from datetime import datetime, timedelta

from sqlalchemy import and_, desc, func, or_
from sqlalchemy.orm import Session

from ...infrastructure.database.models.audit_log import AuditLog, AuditLogRetentionPolicy
from ..logging import get_logger
from .auth_audit import AuditSeverity, AuthAuditEvent, AuthAuditService

logger = get_logger(__name__)


class RetentionManager:
    """
    Manages audit log retention policies and automated cleanup operations.
    Ensures compliance with data retention requirements while optimizing storage.
    """

    def __init__(self, db: Session):
        self.db = db
        self.audit_service = AuthAuditService(db)
        self._default_retention_days = 2555  # 7 years default

    async def apply_retention_policies(self, batch_size: int = 1000) -> dict[str, int]:
        """
        Apply all active retention policies to audit logs.
        Updates retention dates for logs that don't have them set.
        
        Args:
            batch_size: Number of logs to process in each batch
            
        Returns:
            Dictionary with processing statistics
        """
        try:
            stats = {
                "processed": 0,
                "updated": 0,
                "errors": 0,
                "policies_applied": 0
            }

            # Get all active retention policies
            policies = (
                self.db.query(AuditLogRetentionPolicy)
                .filter(AuditLogRetentionPolicy.is_active == True)
                .order_by(desc(AuditLogRetentionPolicy.is_default))  # Process specific policies first
                .all()
            )

            if not policies:
                logger.warning("No active retention policies found")
                return stats

            # Process logs without retention dates in batches
            offset = 0
            while True:
                # Get batch of logs without retention dates
                logs_batch = (
                    self.db.query(AuditLog)
                    .filter(AuditLog.retention_date.is_(None))
                    .offset(offset)
                    .limit(batch_size)
                    .all()
                )

                if not logs_batch:
                    break

                # Apply policies to each log in the batch
                for log in logs_batch:
                    try:
                        applicable_policy = self._find_applicable_policy(log, policies)
                        if applicable_policy:
                            retention_date = self._calculate_retention_date(log, applicable_policy)
                            log.retention_date = retention_date
                            stats["updated"] += 1
                            stats["policies_applied"] += 1
                        else:
                            # Use default retention if no specific policy applies
                            default_retention_date = log.timestamp + timedelta(days=self._default_retention_days)
                            log.retention_date = default_retention_date
                            stats["updated"] += 1

                        stats["processed"] += 1

                    except Exception as e:
                        stats["errors"] += 1
                        logger.error(
                            "Failed to apply retention policy to log",
                            log_id=str(log.id),
                            error=str(e)
                        )

                # Commit batch changes
                try:
                    self.db.commit()
                    logger.debug(
                        "Applied retention policies to batch",
                        batch_size=len(logs_batch),
                        offset=offset,
                        updated=stats["updated"]
                    )
                except Exception as e:
                    self.db.rollback()
                    logger.error(
                        "Failed to commit retention policy batch",
                        error=str(e),
                        offset=offset
                    )
                    stats["errors"] += len(logs_batch)

                offset += batch_size

            logger.info(
                "Retention policy application completed",
                **stats
            )

            return stats

        except Exception as e:
            self.db.rollback()
            logger.error(
                "Failed to apply retention policies",
                error=str(e)
            )
            raise

    async def cleanup_expired_logs(
        self,
        batch_size: int = 1000,
        dry_run: bool = False,
        max_age_days: int | None = None
    ) -> dict[str, int]:
        """
        Clean up audit logs that have passed their retention date.
        
        Args:
            batch_size: Number of logs to process in each batch
            dry_run: If True, only count logs that would be deleted
            max_age_days: Additional age limit (logs older than this are always deleted)
            
        Returns:
            Dictionary with cleanup statistics
        """
        try:
            stats = {
                "identified": 0,
                "deleted": 0,
                "archived": 0,
                "errors": 0,
                "data_freed_mb": 0
            }

            # Build query for expired logs
            query = self.db.query(AuditLog)

            conditions = []

            # Logs past their retention date
            conditions.append(
                and_(
                    AuditLog.retention_date.isnot(None),
                    AuditLog.retention_date <= datetime.utcnow()
                )
            )

            # Additional age-based cleanup if specified
            if max_age_days:
                age_cutoff = datetime.utcnow() - timedelta(days=max_age_days)
                conditions.append(AuditLog.timestamp <= age_cutoff)

            query = query.filter(or_(*conditions))

            # Get total count for reporting
            total_expired = query.count()
            stats["identified"] = total_expired

            if dry_run:
                logger.info(
                    "Dry run: Would delete expired logs",
                    count=total_expired
                )
                return stats

            if total_expired == 0:
                logger.info("No expired audit logs found for cleanup")
                return stats

            # Process in batches
            deleted_count = 0
            while True:
                # Get batch of expired logs
                expired_logs = query.limit(batch_size).all()

                if not expired_logs:
                    break

                batch_stats = await self._process_cleanup_batch(expired_logs)

                # Update overall statistics
                stats["deleted"] += batch_stats["deleted"]
                stats["archived"] += batch_stats["archived"]
                stats["errors"] += batch_stats["errors"]
                stats["data_freed_mb"] += batch_stats["data_freed_mb"]

                deleted_count += len(expired_logs)

                logger.debug(
                    "Processed cleanup batch",
                    batch_size=len(expired_logs),
                    total_deleted=stats["deleted"],
                    remaining=total_expired - deleted_count
                )

            # Log cleanup event
            await self.audit_service.log_auth_event(
                event_type=AuthAuditEvent.SYSTEM_START,  # Using closest available event
                action="automated_log_cleanup",
                details={
                    "logs_deleted": stats["deleted"],
                    "logs_archived": stats["archived"],
                    "data_freed_mb": stats["data_freed_mb"],
                    "batch_size": batch_size
                },
                severity=AuditSeverity.INFO,
                success=True
            )

            logger.info(
                "Audit log cleanup completed",
                **stats
            )

            return stats

        except Exception as e:
            self.db.rollback()
            logger.error(
                "Failed to cleanup expired logs",
                error=str(e)
            )
            raise

    async def archive_old_logs(
        self,
        archive_after_days: int = 365,
        batch_size: int = 1000
    ) -> dict[str, int]:
        """
        Archive old audit logs to reduce database size while maintaining compliance.
        
        Args:
            archive_after_days: Archive logs older than this many days
            batch_size: Number of logs to process in each batch
            
        Returns:
            Dictionary with archival statistics
        """
        try:
            stats = {
                "identified": 0,
                "archived": 0,
                "errors": 0,
                "size_archived_mb": 0
            }

            # Calculate archive cutoff date
            archive_cutoff = datetime.utcnow() - timedelta(days=archive_after_days)

            # Find logs eligible for archival
            query = (
                self.db.query(AuditLog)
                .filter(
                    and_(
                        AuditLog.timestamp <= archive_cutoff,
                        AuditLog.retention_date > datetime.utcnow()  # Not yet expired
                    )
                )
            )

            total_to_archive = query.count()
            stats["identified"] = total_to_archive

            if total_to_archive == 0:
                logger.info("No audit logs eligible for archival")
                return stats

            logger.info(
                "Starting audit log archival",
                total_logs=total_to_archive,
                cutoff_date=archive_cutoff.isoformat()
            )

            # Process in batches
            offset = 0
            while offset < total_to_archive:
                batch_logs = query.offset(offset).limit(batch_size).all()

                if not batch_logs:
                    break

                # Archive batch (implementation would depend on archive storage)
                batch_archived = await self._archive_log_batch(batch_logs)

                stats["archived"] += batch_archived["count"]
                stats["size_archived_mb"] += batch_archived["size_mb"]

                offset += batch_size

                logger.debug(
                    "Archived log batch",
                    batch_size=len(batch_logs),
                    total_archived=stats["archived"],
                    progress_pct=int((offset / total_to_archive) * 100)
                )

            # Log archival event
            await self.audit_service.log_auth_event(
                event_type=AuthAuditEvent.SYSTEM_START,  # Using closest available event
                action="automated_log_archival",
                details={
                    "logs_archived": stats["archived"],
                    "size_archived_mb": stats["size_archived_mb"],
                    "archive_cutoff_days": archive_after_days
                },
                severity=AuditSeverity.INFO,
                success=True
            )

            logger.info(
                "Audit log archival completed",
                **stats
            )

            return stats

        except Exception as e:
            logger.error(
                "Failed to archive old logs",
                error=str(e)
            )
            raise

    async def get_retention_summary(self) -> dict[str, any]:
        """
        Get a summary of current retention status and storage usage.
        
        Returns:
            Dictionary with retention summary statistics
        """
        try:
            summary = {}

            # Total log counts
            total_logs = self.db.query(func.count(AuditLog.id)).scalar()
            summary["total_logs"] = total_logs

            # Logs with/without retention dates
            logs_with_retention = (
                self.db.query(func.count(AuditLog.id))
                .filter(AuditLog.retention_date.isnot(None))
                .scalar()
            )
            summary["logs_with_retention"] = logs_with_retention
            summary["logs_without_retention"] = total_logs - logs_with_retention

            # Expired logs
            expired_logs = (
                self.db.query(func.count(AuditLog.id))
                .filter(
                    and_(
                        AuditLog.retention_date.isnot(None),
                        AuditLog.retention_date <= datetime.utcnow()
                    )
                )
                .scalar()
            )
            summary["expired_logs"] = expired_logs

            # Logs by age categories
            now = datetime.utcnow()

            # Last 30 days
            recent_logs = (
                self.db.query(func.count(AuditLog.id))
                .filter(AuditLog.timestamp >= now - timedelta(days=30))
                .scalar()
            )
            summary["logs_last_30_days"] = recent_logs

            # 30-365 days old
            medium_age_logs = (
                self.db.query(func.count(AuditLog.id))
                .filter(
                    and_(
                        AuditLog.timestamp >= now - timedelta(days=365),
                        AuditLog.timestamp < now - timedelta(days=30)
                    )
                )
                .scalar()
            )
            summary["logs_30_365_days"] = medium_age_logs

            # Older than 1 year
            old_logs = (
                self.db.query(func.count(AuditLog.id))
                .filter(AuditLog.timestamp < now - timedelta(days=365))
                .scalar()
            )
            summary["logs_over_1_year"] = old_logs

            # Active retention policies
            active_policies = (
                self.db.query(func.count(AuditLogRetentionPolicy.id))
                .filter(AuditLogRetentionPolicy.is_active == True)
                .scalar()
            )
            summary["active_retention_policies"] = active_policies

            # Sensitive logs
            sensitive_logs = (
                self.db.query(func.count(AuditLog.id))
                .filter(AuditLog.is_sensitive == True)
                .scalar()
            )
            summary["sensitive_logs"] = sensitive_logs

            # Calculate storage estimates (rough estimates)
            avg_log_size_kb = 2  # Estimated average log entry size
            summary["estimated_storage_mb"] = int((total_logs * avg_log_size_kb) / 1024)
            summary["potential_cleanup_mb"] = int((expired_logs * avg_log_size_kb) / 1024)

            return summary

        except Exception as e:
            logger.error(
                "Failed to generate retention summary",
                error=str(e)
            )
            raise

    def _find_applicable_policy(
        self,
        log: AuditLog,
        policies: list[AuditLogRetentionPolicy]
    ) -> AuditLogRetentionPolicy | None:
        """Find the most specific retention policy that applies to a log."""
        # First pass: look for exact matches
        for policy in policies:
            if policy.is_default:
                continue  # Skip default policy in first pass

            if policy.applies_to_event(
                log.event_type,
                log.event_category,
                log.severity,
                log.compliance_tags or []
            ):
                return policy

        # Second pass: look for default policy
        for policy in policies:
            if policy.is_default:
                return policy

        return None

    def _calculate_retention_date(
        self,
        log: AuditLog,
        policy: AuditLogRetentionPolicy
    ) -> datetime:
        """Calculate the retention date for a log based on the policy."""
        return log.timestamp + timedelta(days=policy.retention_days)

    async def _process_cleanup_batch(self, logs_batch: list[AuditLog]) -> dict[str, int]:
        """Process a batch of logs for cleanup."""
        batch_stats = {
            "deleted": 0,
            "archived": 0,
            "errors": 0,
            "data_freed_mb": 0
        }

        try:
            # Estimate data size (rough calculation)
            estimated_size_kb = len(logs_batch) * 2  # 2KB average per log
            batch_stats["data_freed_mb"] = int(estimated_size_kb / 1024)

            # Delete logs in this batch
            for log in logs_batch:
                try:
                    self.db.delete(log)
                    batch_stats["deleted"] += 1
                except Exception as e:
                    batch_stats["errors"] += 1
                    logger.error(
                        "Failed to delete log",
                        log_id=str(log.id),
                        error=str(e)
                    )

            # Commit batch deletion
            self.db.commit()

        except Exception as e:
            self.db.rollback()
            batch_stats["errors"] = len(logs_batch)
            logger.error(
                "Failed to process cleanup batch",
                error=str(e),
                batch_size=len(logs_batch)
            )

        return batch_stats

    async def _archive_log_batch(self, logs_batch: list[AuditLog]) -> dict[str, any]:
        """Archive a batch of logs (placeholder implementation)."""
        # In a real implementation, this would:
        # 1. Export logs to archive storage (S3, file system, etc.)
        # 2. Compress the data
        # 3. Encrypt if required
        # 4. Update logs to mark as archived
        # 5. Optionally remove from main database

        batch_stats = {
            "count": len(logs_batch),
            "size_mb": int((len(logs_batch) * 2) / 1024)  # Rough estimate
        }

        # Placeholder: just log the archival
        logger.info(
            "Archiving log batch (placeholder)",
            count=batch_stats["count"],
            size_mb=batch_stats["size_mb"]
        )

        return batch_stats


class RetentionScheduler:
    """
    Scheduler for automated retention policy application and cleanup operations.
    Runs retention tasks on a regular schedule.
    """

    def __init__(self, db_session_factory):
        self.db_session_factory = db_session_factory
        self.is_running = False

    async def start_scheduler(self):
        """Start the retention scheduler with automatic tasks."""
        if self.is_running:
            logger.warning("Retention scheduler is already running")
            return

        self.is_running = True
        logger.info("Starting audit log retention scheduler")

        try:
            while self.is_running:
                # Run retention tasks
                await self._run_scheduled_tasks()

                # Wait 24 hours before next run
                await asyncio.sleep(24 * 60 * 60)

        except Exception as e:
            logger.error(
                "Retention scheduler encountered error",
                error=str(e)
            )
        finally:
            self.is_running = False

    def stop_scheduler(self):
        """Stop the retention scheduler."""
        logger.info("Stopping audit log retention scheduler")
        self.is_running = False

    async def _run_scheduled_tasks(self):
        """Run the scheduled retention and cleanup tasks."""
        try:
            # Get database session
            db_session = self.db_session_factory()
            retention_manager = RetentionManager(db_session)

            logger.info("Starting scheduled retention tasks")

            # 1. Apply retention policies to new logs
            logger.info("Applying retention policies")
            policy_stats = await retention_manager.apply_retention_policies()

            # 2. Clean up expired logs
            logger.info("Cleaning up expired logs")
            cleanup_stats = await retention_manager.cleanup_expired_logs()

            # 3. Archive old logs (if configured)
            logger.info("Archiving old logs")
            archive_stats = await retention_manager.archive_old_logs()

            # 4. Generate summary
            summary = await retention_manager.get_retention_summary()

            logger.info(
                "Scheduled retention tasks completed",
                policy_stats=policy_stats,
                cleanup_stats=cleanup_stats,
                archive_stats=archive_stats,
                summary=summary
            )

        except Exception as e:
            logger.error(
                "Failed to run scheduled retention tasks",
                error=str(e)
            )
        finally:
            if db_session:
                db_session.close()
