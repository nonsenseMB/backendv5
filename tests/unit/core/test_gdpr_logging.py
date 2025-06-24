"""Tests for GDPR compliance features in logging."""
import json
import tempfile
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import patch

from src.core.logging.gdpr import GDPRLogManager
from src.core.logging.retention import LogRetentionManager


class TestLogRetentionManager:
    """Test log retention for GDPR compliance."""

    def test_cleanup_old_logs(self):
        """Test automatic cleanup of old log files."""
        with tempfile.TemporaryDirectory() as temp_dir:
            log_dir = Path(temp_dir)
            retention_manager = LogRetentionManager(retention_days=7, dry_run=True)

            # Create test log files with different ages
            old_file = log_dir / "old.log"
            new_file = log_dir / "new.log"

            old_file.write_text("old log content")
            new_file.write_text("new log content")

            # Simulate old file (10 days ago)
            import os
            old_time = datetime.now() - timedelta(days=10)
            os.utime(old_file, times=(old_time.timestamp(), old_time.timestamp()))

            # Run cleanup
            import asyncio
            stats = asyncio.run(retention_manager.cleanup_old_logs(log_dir))

            assert stats["deleted_files"] == 1
            assert stats["dry_run"] is True
            assert old_file.exists()  # Should still exist in dry run

    def test_cleanup_by_size(self):
        """Test cleanup based on directory size."""
        with tempfile.TemporaryDirectory() as temp_dir:
            log_dir = Path(temp_dir)
            retention_manager = LogRetentionManager(dry_run=True)

            # Create large test files
            for i in range(3):
                large_file = log_dir / f"large_{i}.log"
                large_file.write_text("x" * 1024 * 1024)  # 1MB each

            # Test size-based cleanup
            import asyncio
            stats = asyncio.run(retention_manager.cleanup_by_size(log_dir, max_size_mb=2))

            assert stats.get("deleted_files", 0) > 0 or stats.get("current_size_mb", 0) > 0


class TestGDPRLogManager:
    """Test GDPR compliance features."""

    def test_erase_user_data(self):
        """Test user data erasure (Right to be forgotten)."""
        with tempfile.TemporaryDirectory() as temp_dir:
            log_dir = Path(temp_dir)
            gdpr_manager = GDPRLogManager(log_dir)

            # Create test log file with user data
            log_file = log_dir / "test.log"
            test_logs = [
                {"timestamp": "2025-01-01T12:00:00", "user_id": "user123", "event": "login"},
                {"timestamp": "2025-01-01T12:01:00", "user_id": "user456", "event": "login"},
                {"timestamp": "2025-01-01T12:02:00", "user_id": "user123", "event": "logout"},
                {"timestamp": "2025-01-01T12:03:00", "user_id": "user789", "event": "login"},
            ]

            with open(log_file, 'w') as f:
                for log_entry in test_logs:
                    f.write(json.dumps(log_entry) + "\n")

            # Test erasure
            stats = gdpr_manager.erase_user_data("user123", "admin", backup_before_deletion=False)

            assert stats["entries_removed"] == 2
            assert stats["files_processed"] == 1
            assert len(stats["errors"]) == 0

            # Verify user data was removed
            remaining_logs = []
            with open(log_file) as f:
                for line in f:
                    remaining_logs.append(json.loads(line.strip()))

            # Should only have user456 and user789 entries
            user_ids = [log["user_id"] for log in remaining_logs]
            assert "user123" not in user_ids
            assert "user456" in user_ids
            assert "user789" in user_ids

    def test_export_user_data(self):
        """Test user data export (Data portability)."""
        with tempfile.TemporaryDirectory() as temp_dir:
            log_dir = Path(temp_dir)
            gdpr_manager = GDPRLogManager(log_dir)

            # Create test log file
            log_file = log_dir / "test.log"
            test_logs = [
                {"timestamp": "2025-01-01T12:00:00", "user_id": "user123", "event": "login", "ip": "192.168.1.1"},
                {"timestamp": "2025-01-01T12:01:00", "user_id": "user456", "event": "login"},
                {"timestamp": "2025-01-01T12:02:00", "user_id": "user123", "event": "data_access", "resource": "documents"},
            ]

            with open(log_file, 'w') as f:
                for log_entry in test_logs:
                    f.write(json.dumps(log_entry) + "\n")

            # Test export
            with patch('src.core.logging.gdpr.log_audit_event'):
                export_data = gdpr_manager.export_user_data("user123", "admin")

            assert export_data["metadata"]["user_id"] == "user123"
            assert export_data["statistics"]["total_entries"] == 2
            assert len(export_data["logs"]) == 2

            # Verify exported data contains correct entries
            exported_events = [log["event"] for log in export_data["logs"]]
            assert "login" in exported_events
            assert "data_access" in exported_events

    def test_search_user_references(self):
        """Test searching for user references in logs."""
        with tempfile.TemporaryDirectory() as temp_dir:
            log_dir = Path(temp_dir)
            gdpr_manager = GDPRLogManager(log_dir)

            # Create test log file
            log_file = log_dir / "test.log"
            test_logs = [
                {"timestamp": "2025-01-01T12:00:00", "user_id": "user123", "event": "login"},
                {"timestamp": "2025-01-01T12:01:00", "email": "user123@example.com", "event": "password_reset"},
                {"timestamp": "2025-01-01T12:02:00", "user_id": "user456", "event": "login"},
            ]

            with open(log_file, 'w') as f:
                for log_entry in test_logs:
                    f.write(json.dumps(log_entry) + "\n")

            # Search for user references
            results = gdpr_manager.search_user_references("user123")

            assert results["total_matches"] == 2
            assert results["files_searched"] == 1
            assert str(log_file) in results["matches_by_file"]

    @patch('src.core.logging.gdpr.log_audit_event')
    def test_audit_logging_for_gdpr_operations(self, mock_audit):
        """Test that GDPR operations are properly audited."""
        with tempfile.TemporaryDirectory() as temp_dir:
            log_dir = Path(temp_dir)
            gdpr_manager = GDPRLogManager(log_dir)

            # Create empty log file
            log_file = log_dir / "test.log"
            log_file.write_text('{"user_id": "user123", "event": "test"}\n')

            # Test erasure audit logging
            gdpr_manager.erase_user_data("user123", "admin", backup_before_deletion=False)

            # Verify audit events were logged
            assert mock_audit.call_count >= 2  # Start and completion events

            # Check that erasure events were logged
            calls = mock_audit.call_args_list
            event_types = [call[1]["event_type"] for call in calls]
            assert any("DATA_ERASURE_REQUEST" in str(event_type) for event_type in event_types)


class TestGDPRCompliance:
    """Integration tests for GDPR compliance."""

    def test_pii_filtering_enabled_by_default(self):
        """Test that PII filtering is enabled by default."""
        from src.core.logging.config import LogConfig

        config = LogConfig()
        assert config.enable_pii_filtering is True
        assert config.log_retention_days == 90

    def test_retention_settings_configurable(self):
        """Test that retention settings are configurable."""
        from src.core.logging.config import LogConfig

        config = LogConfig(log_retention_days=30)
        assert config.log_retention_days == 30

    @patch('src.core.logging.filters.PIIRedactionFilter')
    @patch('builtins.print')
    def test_pii_filter_activation_logging(self, mock_print, mock_filter):
        """Test that PII filter activation is logged."""
        from src.core.logging.config import LogConfig, configure_logging

        # Test with PII filtering enabled
        config = LogConfig(enable_pii_filtering=True)
        configure_logging(config)

        # Verify filter was created and activation was logged
        mock_filter.assert_called_once()
        mock_print.assert_any_call("🔒 PII filtering ENABLED for GDPR compliance")

    @patch('builtins.print')
    def test_pii_filter_disabled_warning(self, mock_print):
        """Test warning when PII filtering is disabled."""
        from src.core.logging.config import LogConfig, configure_logging

        # Test with PII filtering disabled
        config = LogConfig(enable_pii_filtering=False)
        configure_logging(config)

        # Verify warning was logged
        mock_print.assert_any_call("⚠️  WARNING: PII filtering DISABLED - potential GDPR violation!")

    def test_gdpr_audit_events_defined(self):
        """Test that GDPR-specific audit events are defined."""
        from src.core.logging.audit import AuditEventType

        # Verify GDPR events exist
        assert hasattr(AuditEventType, 'CONSENT_GIVEN')
        assert hasattr(AuditEventType, 'CONSENT_WITHDRAWN')
        assert hasattr(AuditEventType, 'DATA_ERASURE_REQUEST')
        assert hasattr(AuditEventType, 'DATA_PORTABILITY_REQUEST')

        # Test enum values
        assert AuditEventType.CONSENT_GIVEN.value == "CONSENT_GIVEN"
        assert AuditEventType.DATA_ERASURE_REQUEST.value == "DATA_ERASURE_REQUEST"
