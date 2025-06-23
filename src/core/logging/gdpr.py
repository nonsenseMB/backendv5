"""GDPR compliance features for log management.

This module provides tools for:
- Right to erasure (Art. 17 DSGVO)
- Data portability (Art. 20 DSGVO)
- Consent tracking
- User data extraction from logs
"""

import gzip
import json
import shutil
from datetime import datetime
from pathlib import Path
from typing import Any

import structlog

from .audit import AuditEventType, AuditSeverity, log_audit_event

logger = structlog.get_logger(__name__)


class GDPRLogManager:
    """Manager for GDPR-compliant log operations."""

    def __init__(self, log_directory: Path):
        """Initialize GDPR log manager.

        Args:
            log_directory: Directory containing log files
        """
        self.log_directory = log_directory
        self.processed_files: list[Path] = []
        self.errors: list[str] = []

    def erase_user_data(
        self,
        user_id: str,
        requester_id: str,
        backup_before_deletion: bool = True
    ) -> dict[str, Any]:
        """Erase all data for a specific user (Right to Erasure - Art. 17 DSGVO).

        Args:
            user_id: ID of the user whose data should be erased
            requester_id: ID of the person requesting the erasure
            backup_before_deletion: Whether to create backup before deletion

        Returns:
            Dictionary with erasure statistics
        """
        logger.info(
            "Starting user data erasure",
            user_id=user_id,
            requester_id=requester_id,
            backup=backup_before_deletion
        )

        # Log the erasure request
        log_audit_event(
            event_type=AuditEventType.DATA_ERASURE_REQUEST,
            user_id=requester_id,
            details={
                "target_user_id": user_id,
                "backup_created": backup_before_deletion,
                "erasure_type": "complete_user_data"
            },
            severity=AuditSeverity.CRITICAL
        )

        erasure_stats = {
            "user_id": user_id,
            "requester_id": requester_id,
            "timestamp": datetime.utcnow().isoformat(),
            "files_processed": 0,
            "entries_removed": 0,
            "backup_created": backup_before_deletion,
            "errors": []
        }

        try:
            # Create backup if requested
            if backup_before_deletion:
                backup_path = self._create_user_backup(user_id)
                erasure_stats["backup_path"] = str(backup_path)

            # Process all log files
            log_files = self._find_log_files()

            for log_file in log_files:
                try:
                    removed_count = self._remove_user_from_log_file(user_id, log_file)
                    erasure_stats["entries_removed"] += removed_count
                    erasure_stats["files_processed"] += 1

                    if removed_count > 0:
                        logger.info(
                            "Removed user entries from log file",
                            file=str(log_file),
                            entries_removed=removed_count,
                            user_id=user_id
                        )

                except Exception as e:
                    error_msg = f"Failed to process {log_file}: {str(e)}"
                    erasure_stats["errors"].append(error_msg)
                    logger.error("Log file processing failed", file=str(log_file), error=str(e))

            # Log completion
            log_audit_event(
                event_type=AuditEventType.DATA_ERASURE_REQUEST,
                user_id=requester_id,
                details={
                    "target_user_id": user_id,
                    "completion_status": "success",
                    "files_processed": erasure_stats["files_processed"],
                    "entries_removed": erasure_stats["entries_removed"],
                    "errors_count": len(erasure_stats["errors"])
                },
                severity=AuditSeverity.CRITICAL
            )

            logger.info(
                "User data erasure completed",
                user_id=user_id,
                files_processed=erasure_stats["files_processed"],
                entries_removed=erasure_stats["entries_removed"]
            )

        except Exception as e:
            erasure_stats["errors"].append(f"Critical error: {str(e)}")
            logger.error("User data erasure failed", user_id=user_id, error=str(e))

        return erasure_stats

    def export_user_data(self, user_id: str, requester_id: str) -> dict[str, Any]:
        """Export all data for a specific user (Data Portability - Art. 20 DSGVO).

        Args:
            user_id: ID of the user whose data should be exported
            requester_id: ID of the person requesting the export

        Returns:
            Dictionary containing all user data from logs
        """
        logger.info(
            "Starting user data export",
            user_id=user_id,
            requester_id=requester_id
        )

        # Log the export request
        log_audit_event(
            event_type=AuditEventType.DATA_PORTABILITY_REQUEST,
            user_id=requester_id,
            details={
                "target_user_id": user_id,
                "export_type": "complete_user_logs"
            },
            severity=AuditSeverity.HIGH
        )

        export_data = {
            "metadata": {
                "user_id": user_id,
                "requester_id": requester_id,
                "export_date": datetime.utcnow().isoformat(),
                "gdpr_article": "Article 20 - Right to data portability"
            },
            "logs": [],
            "statistics": {
                "files_processed": 0,
                "total_entries": 0,
                "date_range": {"earliest": None, "latest": None}
            }
        }

        try:
            log_files = self._find_log_files()

            for log_file in log_files:
                try:
                    user_entries = self._extract_user_from_log_file(user_id, log_file)
                    if user_entries:
                        export_data["logs"].extend(user_entries)
                        export_data["statistics"]["total_entries"] += len(user_entries)

                        # Track date range
                        for entry in user_entries:
                            timestamp = entry.get("timestamp")
                            if timestamp:
                                if not export_data["statistics"]["date_range"]["earliest"]:
                                    export_data["statistics"]["date_range"]["earliest"] = timestamp
                                    export_data["statistics"]["date_range"]["latest"] = timestamp
                                else:
                                    if timestamp < export_data["statistics"]["date_range"]["earliest"]:
                                        export_data["statistics"]["date_range"]["earliest"] = timestamp
                                    if timestamp > export_data["statistics"]["date_range"]["latest"]:
                                        export_data["statistics"]["date_range"]["latest"] = timestamp

                    export_data["statistics"]["files_processed"] += 1

                except Exception as e:
                    logger.error("Failed to export from log file", file=str(log_file), error=str(e))

            # Save export to file
            export_file = self._save_export_file(user_id, export_data)
            export_data["metadata"]["export_file"] = str(export_file)

            # Log completion
            log_audit_event(
                event_type=AuditEventType.DATA_PORTABILITY_REQUEST,
                user_id=requester_id,
                details={
                    "target_user_id": user_id,
                    "completion_status": "success",
                    "total_entries": export_data["statistics"]["total_entries"],
                    "export_file": str(export_file)
                },
                severity=AuditSeverity.HIGH
            )

            logger.info(
                "User data export completed",
                user_id=user_id,
                total_entries=export_data["statistics"]["total_entries"],
                export_file=str(export_file)
            )

        except Exception as e:
            logger.error("User data export failed", user_id=user_id, error=str(e))
            export_data["error"] = str(e)

        return export_data

    def _find_log_files(self) -> list[Path]:
        """Find all log files in the directory."""
        log_files = []
        patterns = ["*.log", "*.log.*", "*.json", "*.audit"]

        for pattern in patterns:
            log_files.extend(self.log_directory.glob(pattern))

        return sorted(log_files)

    def _remove_user_from_log_file(self, user_id: str, log_file: Path) -> int:
        """Remove all entries for a specific user from a log file."""
        removed_count = 0
        temp_file = log_file.with_suffix(log_file.suffix + ".tmp")

        try:
            with open(log_file, encoding='utf-8') as infile, \
                 open(temp_file, 'w', encoding='utf-8') as outfile:

                for line in infile:
                    try:
                        # Try to parse as JSON
                        log_entry = json.loads(line.strip())

                        # Check if this entry belongs to the user
                        if (log_entry.get('user_id') == user_id or
                            log_entry.get('target_user_id') == user_id or
                            log_entry.get('data_subject_id') == user_id):
                            removed_count += 1
                            continue  # Skip this line (remove it)

                    except json.JSONDecodeError:
                        # Keep non-JSON lines as-is
                        pass

                    # Keep this line
                    outfile.write(line)

            # Replace original file with cleaned version
            if removed_count > 0:
                shutil.move(temp_file, log_file)
            else:
                temp_file.unlink()  # Remove temp file if no changes

        except Exception as e:
            if temp_file.exists():
                temp_file.unlink()
            raise e

        return removed_count

    def _extract_user_from_log_file(self, user_id: str, log_file: Path) -> list[dict[str, Any]]:
        """Extract all entries for a specific user from a log file."""
        user_entries = []

        try:
            with open(log_file, encoding='utf-8') as infile:
                for line in infile:
                    try:
                        log_entry = json.loads(line.strip())

                        # Check if this entry belongs to the user
                        if (log_entry.get('user_id') == user_id or
                            log_entry.get('target_user_id') == user_id or
                            log_entry.get('data_subject_id') == user_id):

                            # Add source file information
                            log_entry['_source_file'] = str(log_file)
                            user_entries.append(log_entry)

                    except json.JSONDecodeError:
                        continue  # Skip non-JSON lines

        except Exception as e:
            logger.error("Failed to extract user data", file=str(log_file), error=str(e))

        return user_entries

    def _create_user_backup(self, user_id: str) -> Path:
        """Create a backup of user data before deletion."""
        backup_dir = self.log_directory / "gdpr_backups"
        backup_dir.mkdir(exist_ok=True)

        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        backup_file = backup_dir / f"user_{user_id}_backup_{timestamp}.json.gz"

        # Export user data
        export_data = self.export_user_data(user_id, "system_backup")

        # Save as compressed JSON
        with gzip.open(backup_file, 'wt', encoding='utf-8') as f:
            json.dump(export_data, f, indent=2, ensure_ascii=False)

        logger.info("Created user data backup", user_id=user_id, backup_file=str(backup_file))
        return backup_file

    def _save_export_file(self, user_id: str, export_data: dict[str, Any]) -> Path:
        """Save export data to a file."""
        export_dir = self.log_directory / "gdpr_exports"
        export_dir.mkdir(exist_ok=True)

        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        export_file = export_dir / f"user_{user_id}_export_{timestamp}.json"

        with open(export_file, 'w', encoding='utf-8') as f:
            json.dump(export_data, f, indent=2, ensure_ascii=False)

        return export_file

    def search_user_references(self, identifier: str) -> dict[str, Any]:
        """Search for any references to a user identifier in logs.

        This can help identify all places where user data might exist.

        Args:
            identifier: User identifier to search for (ID, email, etc.)

        Returns:
            Dictionary with search results
        """
        results = {
            "identifier": identifier,
            "search_date": datetime.utcnow().isoformat(),
            "files_searched": 0,
            "total_matches": 0,
            "matches_by_file": {}
        }

        log_files = self._find_log_files()

        for log_file in log_files:
            matches = []
            try:
                with open(log_file, encoding='utf-8') as f:
                    for line_num, line in enumerate(f, 1):
                        if identifier.lower() in line.lower():
                            try:
                                log_entry = json.loads(line.strip())
                                matches.append({
                                    "line_number": line_num,
                                    "timestamp": log_entry.get("timestamp"),
                                    "event": log_entry.get("event", "unknown"),
                                    "context": line.strip()[:200] + "..." if len(line) > 200 else line.strip()
                                })
                            except json.JSONDecodeError:
                                matches.append({
                                    "line_number": line_num,
                                    "context": line.strip()[:200] + "..." if len(line) > 200 else line.strip()
                                })

                if matches:
                    results["matches_by_file"][str(log_file)] = matches
                    results["total_matches"] += len(matches)

                results["files_searched"] += 1

            except Exception as e:
                logger.error("Failed to search in log file", file=str(log_file), error=str(e))

        return results
