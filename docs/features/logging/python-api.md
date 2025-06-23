# Logging Python API Reference

## Core Functions

### `get_logger`

Get a configured logger instance with optional context binding.

```python
def get_logger(name: str | None = None, **kwargs: Any) -> structlog.BoundLogger
```

**Parameters:**
- `name` (str, optional): Logger name. If None, uses calling module name
- `**kwargs`: Additional context to bind to the logger

**Returns:**
- `structlog.BoundLogger`: Configured logger instance

**Example:**
```python
from src.core.logging import get_logger

# Basic usage
logger = get_logger(__name__)

# With context
logger = get_logger("my_service", tenant_id="tenant_123", service="api")

# Use the logger
logger.info("Service started")
logger.error("Connection failed", error="Timeout", retry_count=3)
```

### `configure_logging`

Configure the logging system with structlog.

```python
def configure_logging(config: LogConfig | None = None) -> None
```

**Parameters:**
- `config` (LogConfig, optional): Logging configuration. If None, reads from environment

**Example:**
```python
from src.core.logging import configure_logging, LogConfig

# Use environment variables
configure_logging()

# Use custom config
config = LogConfig(
    level="DEBUG",
    format="console",
    log_file_path="/custom/path/app.log",
    enable_pii_filtering=True
)
configure_logging(config)
```

## Configuration Classes

### `LogConfig`

Main configuration class for the logging system.

```python
class LogConfig(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="LOG_",
        case_sensitive=False,
        env_file=".env"
    )
    
    level: LogLevel = Field(default=LogLevel.INFO)
    format: LogFormat = Field(default=LogFormat.JSON)
    add_timestamp: bool = Field(default=True)
    add_caller_info: bool = Field(default=True)
    add_thread_info: bool = Field(default=False)
    enable_pii_filtering: bool = Field(default=True)
    log_retention_days: int = Field(default=90)
    enable_tamper_protection: bool = Field(default=True)
    log_file_path: str = Field(default="/var/log/app/backend.log")
```

**Environment Variables:**
| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| LOG_LEVEL | str | INFO | Minimum log level (DEBUG, INFO, WARNING, ERROR, CRITICAL) |
| LOG_FORMAT | str | json | Output format (json, console) |
| LOG_ADD_TIMESTAMP | bool | true | Add timestamp to log entries |
| LOG_ADD_CALLER_INFO | bool | true | Add file/line/function information |
| LOG_ADD_THREAD_INFO | bool | false | Add thread/process information |
| LOG_ENABLE_PII_FILTERING | bool | true | Enable automatic PII redaction |
| LOG_RETENTION_DAYS | int | 90 | Days to retain logs (GDPR requirement) |
| LOG_ENABLE_TAMPER_PROTECTION | bool | true | Enable cryptographic log signing |
| LOG_FILE_PATH | str | /var/log/app/backend.log | Path for log files |

### `LogLevel`

Supported log levels enumeration.

```python
class LogLevel(str, Enum):
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"
```

### `LogFormat`

Output format options.

```python
class LogFormat(str, Enum):
    JSON = "json"      # Structured JSON output
    CONSOLE = "console"  # Human-readable console output
```

## Audit Logging

### `log_audit_event`

Log an audit event with automatic context injection.

```python
def log_audit_event(
    event_type: AuditEventType,
    severity: AuditSeverity = AuditSeverity.MEDIUM,
    user_id: str | None = None,
    resource: str | None = None,
    action: str | None = None,
    result: str | None = None,
    ip_address: str | None = None,
    user_agent: str | None = None,
    **extra_fields: Any
) -> None
```

**Parameters:**
- `event_type` (AuditEventType): Type of audit event
- `severity` (AuditSeverity): Event severity level
- `user_id` (str, optional): User performing the action
- `resource` (str, optional): Resource being accessed
- `action` (str, optional): Action performed
- `result` (str, optional): Result of the action
- `ip_address` (str, optional): Client IP address
- `user_agent` (str, optional): Client user agent
- `**extra_fields`: Additional fields to log

**Example:**
```python
from src.core.logging.audit import log_audit_event, AuditEventType, AuditSeverity

log_audit_event(
    event_type=AuditEventType.LOGIN_SUCCESS,
    user_id="user_123",
    ip_address="192.168.1.100",
    user_agent="Mozilla/5.0...",
    severity=AuditSeverity.LOW
)

log_audit_event(
    event_type=AuditEventType.DATA_ACCESS,
    user_id="admin_456",
    resource="user:789:profile",
    action="read",
    result="success",
    severity=AuditSeverity.MEDIUM,
    reason="Support ticket #1234"
)
```

### `AuditEventType`

Predefined audit event types.

```python
class AuditEventType(Enum):
    # Authentication events
    LOGIN_ATTEMPT = "LOGIN_ATTEMPT"
    LOGIN_SUCCESS = "LOGIN_SUCCESS"
    LOGIN_FAILURE = "LOGIN_FAILURE"
    LOGOUT = "LOGOUT"
    PASSWORD_CHANGE = "PASSWORD_CHANGE"
    PASSWORD_RESET = "PASSWORD_RESET"
    MFA_ENABLED = "MFA_ENABLED"
    MFA_DISABLED = "MFA_DISABLED"
    
    # Authorization events
    PERMISSION_GRANTED = "PERMISSION_GRANTED"
    PERMISSION_DENIED = "PERMISSION_DENIED"
    ROLE_ASSIGNED = "ROLE_ASSIGNED"
    ROLE_REVOKED = "ROLE_REVOKED"
    
    # Data access events
    DATA_ACCESS = "DATA_ACCESS"
    DATA_CREATE = "DATA_CREATE"
    DATA_UPDATE = "DATA_UPDATE"
    DATA_DELETE = "DATA_DELETE"
    DATA_EXPORT = "DATA_EXPORT"
    
    # System events
    CONFIG_CHANGE = "CONFIG_CHANGE"
    SYSTEM_START = "SYSTEM_START"
    SYSTEM_STOP = "SYSTEM_STOP"
    ERROR_OCCURRED = "ERROR_OCCURRED"
    
    # GDPR events
    CONSENT_GIVEN = "CONSENT_GIVEN"
    CONSENT_WITHDRAWN = "CONSENT_WITHDRAWN"
    DATA_ERASURE_REQUEST = "DATA_ERASURE_REQUEST"
    DATA_PORTABILITY_REQUEST = "DATA_PORTABILITY_REQUEST"
    DATA_ACCESS_REQUEST = "DATA_ACCESS_REQUEST"
```

### `AuditSeverity`

Audit event severity levels.

```python
class AuditSeverity(Enum):
    LOW = "LOW"        # Informational events
    MEDIUM = "MEDIUM"  # Important business events
    HIGH = "HIGH"      # Security-relevant events
    CRITICAL = "CRITICAL"  # Critical security events
```

## PII Redaction

### `PIIRedactionFilter`

Filter for automatic PII detection and redaction.

```python
class PIIRedactionFilter:
    def __init__(
        self,
        rules: list[RedactionRule] | None = None,
        hash_algorithm: str = "sha256",
        hash_salt: bytes | None = None
    ):
        """Initialize PII redaction filter.
        
        Args:
            rules: Custom redaction rules
            hash_algorithm: Algorithm for pseudonymization
            hash_salt: Salt for hashing (tenant-specific)
        """
```

**Methods:**

#### `add_rule`
```python
def add_rule(self, rule: RedactionRule) -> None:
    """Add a custom redaction rule."""
```

#### `redact`
```python
def redact(self, data: Any) -> tuple[Any, dict[str, int]]:
    """Redact PII from data.
    
    Returns:
        Tuple of (redacted_data, statistics)
    """
```

### `RedactionRule`

Definition for PII redaction patterns.

```python
@dataclass
class RedactionRule:
    name: str                    # Rule identifier
    pattern: re.Pattern         # Regex pattern to match
    replacement: str            # Replacement text
    hash_value: bool = True     # Whether to append hash
    description: str = ""       # Rule description
```

**Example:**
```python
from src.core.logging.filters import PIIRedactionFilter, RedactionRule
import re

# Create custom filter
filter = PIIRedactionFilter()

# Add custom rule for employee IDs
filter.add_rule(RedactionRule(
    name="employee_id",
    pattern=re.compile(r"EMP\d{6}"),
    replacement="[EMPLOYEE_ID]",
    hash_value=True,
    description="Employee identification numbers"
))

# Use the filter
data = {"message": "Employee EMP123456 accessed system"}
redacted, stats = filter.redact(data)
# Result: {"message": "Employee [EMPLOYEE_ID]:a1b2c3 accessed system"}
```

## GDPR Operations

### `GDPRLogManager`

Manager for GDPR-compliant log operations.

```python
class GDPRLogManager:
    def __init__(
        self,
        log_directory: str,
        backup_directory: str | None = None,
        audit_logger: Any | None = None
    ):
        """Initialize GDPR log manager.
        
        Args:
            log_directory: Directory containing log files
            backup_directory: Directory for backups before erasure
            audit_logger: Logger for audit events
        """
```

**Methods:**

#### `erase_user_data`
```python
async def erase_user_data(
    self,
    user_id: str,
    requester_id: str,
    reason: str = "GDPR Article 17 - Right to erasure",
    dry_run: bool = False
) -> dict[str, Any]:
    """Erase all log entries for a specific user.
    
    Args:
        user_id: ID of user whose data to erase
        requester_id: ID of person requesting erasure
        reason: Reason for erasure
        dry_run: If True, only simulate erasure
        
    Returns:
        Dictionary with erasure results
    """
```

#### `export_user_data`
```python
async def export_user_data(
    self,
    user_id: str,
    output_dir: str,
    output_format: str = "json",
    date_from: datetime | None = None,
    date_to: datetime | None = None
) -> str:
    """Export all log data for a user.
    
    Args:
        user_id: ID of user whose data to export
        output_dir: Directory for export file
        output_format: Export format (json, csv, xml)
        date_from: Start date for export
        date_to: End date for export
        
    Returns:
        Path to export file
    """
```

#### `find_user_data`
```python
async def find_user_data(
    self,
    user_id: str,
    include_fields: list[str] | None = None
) -> list[dict[str, Any]]:
    """Find all log entries containing user data.
    
    Args:
        user_id: User ID to search for
        include_fields: Additional fields to search
        
    Returns:
        List of matching log entries
    """
```

**Example:**
```python
from src.core.logging.gdpr import GDPRLogManager

manager = GDPRLogManager(
    log_directory="/var/log/app",
    backup_directory="/secure/gdpr-backups"
)

# Erase user data
result = await manager.erase_user_data(
    user_id="user_123",
    requester_id="admin_456",
    reason="User requested account deletion"
)

# Export user data
export_path = await manager.export_user_data(
    user_id="user_123",
    output_dir="/tmp/exports",
    output_format="json"
)
```

## Log Retention

### `LogRetentionManager`

Manages automatic log cleanup based on retention policies.

```python
class LogRetentionManager:
    def __init__(
        self,
        log_directory: str | Path,
        retention_days: int = 90,
        file_pattern: str = "*.log*",
        audit_logger: Any | None = None
    ):
        """Initialize retention manager.
        
        Args:
            log_directory: Directory to manage
            retention_days: Days to retain logs
            file_pattern: Pattern for log files
            audit_logger: Logger for audit events
        """
```

**Methods:**

#### `cleanup_old_logs`
```python
async def cleanup_old_logs(
    self,
    dry_run: bool = False,
    exclude_patterns: list[str] | None = None
) -> dict[str, Any]:
    """Remove logs older than retention period.
    
    Args:
        dry_run: If True, only simulate cleanup
        exclude_patterns: Patterns to exclude from cleanup
        
    Returns:
        Cleanup statistics
    """
```

#### `cleanup_by_size`
```python
async def cleanup_by_size(
    self,
    max_size_mb: int,
    keep_recent_files: int = 10
) -> dict[str, Any]:
    """Remove oldest logs when size limit exceeded.
    
    Args:
        max_size_mb: Maximum total size in MB
        keep_recent_files: Minimum files to keep
        
    Returns:
        Cleanup statistics
    """
```

#### `schedule_cleanup`
```python
async def schedule_cleanup(
    self,
    check_interval_hours: int = 24,
    cleanup_time: time | None = None
) -> None:
    """Schedule periodic cleanup.
    
    Args:
        check_interval_hours: Hours between checks
        cleanup_time: Specific time to run cleanup
    """
```

**Example:**
```python
from src.core.logging.retention import LogRetentionManager

# Create manager
manager = LogRetentionManager(
    log_directory="/var/log/app",
    retention_days=90,
    file_pattern="backend*.log*"
)

# Manual cleanup
result = await manager.cleanup_old_logs(dry_run=True)
print(f"Would delete {result['files_to_delete']} files")

# Actual cleanup
result = await manager.cleanup_old_logs()
print(f"Deleted {result['files_deleted']} files, freed {result['space_freed_mb']}MB")

# Schedule automatic cleanup
await manager.schedule_cleanup(
    check_interval_hours=24,
    cleanup_time=time(3, 0)  # 3 AM daily
)
```

## Console Rendering

### `RichConsoleRenderer`

Custom console renderer for beautiful structured logs.

```python
class RichConsoleRenderer:
    def __init__(
        self,
        show_path: bool = True,
        show_timestamp: bool = True,
        show_tenant: bool = True
    ):
        """Initialize Rich console renderer.
        
        Args:
            show_path: Show file path and line number
            show_timestamp: Show timestamp
            show_tenant: Show tenant ID
        """
```

**Level Styles:**
| Level | Color | Icon |
|-------|-------|------|
| DEBUG | dim cyan | 🔍 |
| INFO | green | ℹ️ |
| WARNING | yellow | ⚠️ |
| ERROR | red bold | ❌ |
| CRITICAL | red bold reverse | 🚨 |

**Example Output:**
```
2024-01-20T10:30:45Z │ ℹ️     INFO │ src.api.auth auth.py:45 in login() │ tenant=tenant_123 │ User login successful
  user_id: 12345
  duration_ms: 125.5
```

## Context Management

### `get_request_context`

Get current request context for log injection.

```python
def get_request_context() -> RequestContext | None:
    """Get current request context.
    
    Returns:
        RequestContext with tenant_id, request_id, user_id
    """
```

### `set_request_context`

Set request context for automatic log enrichment.

```python
def set_request_context(
    tenant_id: str | None = None,
    request_id: str | None = None,
    user_id: str | None = None
) -> None:
    """Set request context.
    
    Args:
        tenant_id: Current tenant ID
        request_id: Current request ID
        user_id: Current user ID
    """
```

**Example:**
```python
from src.core.context import set_request_context

# In middleware
set_request_context(
    tenant_id="tenant_123",
    request_id="req_abc789",
    user_id="user_456"
)

# All subsequent logs will include this context
logger.info("Processing request")
# Output includes: tenant_id=tenant_123, request_id=req_abc789, user_id=user_456
```

## Progress Logging

### `ProgressLogger`

Logger for tracking long-running operations.

```python
class ProgressLogger:
    def __init__(
        self,
        logger: Any,
        total_items: int,
        operation: str,
        update_interval: int = 100
    ):
        """Initialize progress logger.
        
        Args:
            logger: Base logger to use
            total_items: Total items to process
            operation: Operation description
            update_interval: Log every N items
        """
```

**Example:**
```python
from src.core.logging.progress import ProgressLogger

# Track progress
progress = ProgressLogger(
    logger=logger,
    total_items=10000,
    operation="Processing documents"
)

for i, doc in enumerate(documents):
    process_document(doc)
    progress.update(i + 1)
    
progress.complete()
# Logs: Processing documents: 100% (10000/10000) - 45.2s
```

## Utility Functions

### `mask_sensitive_data`

Manually mask sensitive data in logs.

```python
def mask_sensitive_data(
    data: dict[str, Any],
    fields_to_mask: list[str]
) -> dict[str, Any]:
    """Mask specific fields in data.
    
    Args:
        data: Data dictionary
        fields_to_mask: Field names to mask
        
    Returns:
        Data with masked fields
    """
```

### `create_correlation_id`

Generate correlation ID for distributed tracing.

```python
def create_correlation_id() -> str:
    """Generate unique correlation ID.
    
    Returns:
        UUID string for correlation
    """
```

**Example:**
```python
from src.core.logging.utils import mask_sensitive_data, create_correlation_id

# Mask sensitive fields
data = {"username": "john", "password": "secret123"}
masked = mask_sensitive_data(data, ["password"])
# Result: {"username": "john", "password": "***"}

# Create correlation ID
correlation_id = create_correlation_id()
logger = logger.bind(correlation_id=correlation_id)
```

---

**Python API Version**: 1.0  
**Last Updated**: 2024-01-20  
**Component Version**: v5.0.0