# Logging Migration Guide

## Overview

This guide helps you migrate from previous versions of the nAI Backend logging system to v5. The new system introduces structlog, automatic PII redaction, GDPR compliance features, and improved performance.

## Migration from v4 to v5

### Major Changes

1. **Structlog Integration**: Replaced Python's standard logging with structlog
2. **Automatic PII Redaction**: Built-in PII detection and masking
3. **GDPR Features**: Right to erasure, data export capabilities
4. **Dual Output**: Simultaneous console and file logging
5. **Context Injection**: Automatic request/tenant/user context

### Breaking Changes

#### 1. Logger Initialization

**v4 (Old)**
```python
import logging

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
```

**v5 (New)**
```python
from src.core.logging import get_logger

logger = get_logger(__name__)
# Level is configured globally via LOG_LEVEL env var
```

#### 2. Logging Methods

**v4 (Old)**
```python
# Positional string formatting
logger.info("User %s logged in from %s", user_id, ip_address)

# f-string formatting
logger.error(f"Failed to process {request_id}: {error}")
```

**v5 (New)**
```python
# Structured logging with automatic PII redaction
logger.info("User logged in", user_id=user_id, ip_address=ip_address)

# Error with context
logger.error("Failed to process request", request_id=request_id, error=str(error))
```

#### 3. Configuration

**v4 (Old)**
```python
# logging.conf or logging.yaml
[loggers]
keys=root,app

[handlers]
keys=console,file

[formatters]
keys=standard
```

**v5 (New)**
```bash
# Environment variables
LOG_LEVEL=INFO
LOG_FORMAT=json
LOG_FILE_PATH=/var/log/app/backend.log
LOG_ENABLE_PII_FILTERING=true
LOG_RETENTION_DAYS=90
```

### Step-by-Step Migration

#### Step 1: Update Dependencies

```bash
# Remove old logging dependencies
pip uninstall python-json-logger

# Install new dependencies
pip install structlog rich
```

Update `requirements.txt`:
```diff
- python-json-logger==2.0.7
+ structlog==24.1.0
+ rich==13.7.0
```

#### Step 2: Initialize Logging

Add to your application startup:

```python
# main.py or app.py
from src.core.logging import configure_logging

# Initialize logging before anything else
configure_logging()

# Rest of your application initialization
```

#### Step 3: Update Logger Instances

Find and replace all logger initializations:

```bash
# Find all old logger instances
grep -r "logging.getLogger" src/

# Replace with new pattern
# Use your IDE's find/replace with regex:
# Find: import logging\n.*logger = logging\.getLogger\(__name__\)
# Replace: from src.core.logging import get_logger\nlogger = get_logger(__name__)
```

#### Step 4: Update Log Statements

##### Simple Messages

```python
# Old
logger.info("Application started")

# New (no change needed)
logger.info("Application started")
```

##### Messages with Variables

```python
# Old
logger.info("User %s performed action %s", user_id, action)
logger.info(f"Processing {count} items")

# New
logger.info("User performed action", user_id=user_id, action=action)
logger.info("Processing items", count=count)
```

##### Error Logging

```python
# Old
try:
    process()
except Exception as e:
    logger.error("Processing failed: %s", str(e))
    logger.exception("Full traceback:")

# New
try:
    process()
except Exception as e:
    logger.error("Processing failed", error=str(e), exc_info=True)
```

##### Debug Logging

```python
# Old
logger.debug("Request details: %s", json.dumps(request_data))

# New
logger.debug("Request details", request_data=request_data)
```

#### Step 5: Update Configuration

Replace configuration files with environment variables:

```bash
# Old: logging.conf, logging.yaml, logging.json
# New: .env file

# Development
LOG_LEVEL=DEBUG
LOG_FORMAT=console
LOG_FILE_PATH=./logs/dev.log

# Production
LOG_LEVEL=INFO
LOG_FORMAT=json
LOG_FILE_PATH=/var/log/app/backend.log
LOG_ENABLE_PII_FILTERING=true
LOG_RETENTION_DAYS=90
```

#### Step 6: Update Audit Logging

```python
# Old
audit_logger = logging.getLogger("audit")
audit_logger.info(json.dumps({
    "event": "login",
    "user": user_id,
    "ip": ip_address,
    "timestamp": datetime.utcnow().isoformat()
}))

# New
from src.core.logging.audit import log_audit_event, AuditEventType

log_audit_event(
    event_type=AuditEventType.LOGIN_SUCCESS,
    user_id=user_id,
    ip_address=ip_address  # Automatically redacted
)
```

#### Step 7: Update Custom Handlers

If you have custom log handlers:

```python
# Old
class CustomHandler(logging.Handler):
    def emit(self, record):
        # Custom logic
        pass

# New
from structlog.processors import Processor

class CustomProcessor:
    def __call__(self, logger, method_name, event_dict):
        # Custom logic
        return event_dict

# Add to configuration
configure_logging(custom_processors=[CustomProcessor()])
```

### Migration Script

Use this script to help automate the migration:

```python
#!/usr/bin/env python3
"""Migrate logging from v4 to v5."""

import os
import re
from pathlib import Path
from typing import List, Tuple

def find_python_files(directory: str) -> List[Path]:
    """Find all Python files in directory."""
    return list(Path(directory).rglob("*.py"))

def migrate_imports(content: str) -> Tuple[str, int]:
    """Migrate import statements."""
    changes = 0
    
    # Replace logging imports
    pattern = r'import logging\s*\n(.*?)logger = logging\.getLogger\((.*?)\)'
    replacement = r'from src.core.logging import get_logger\n\1logger = get_logger(\2)'
    
    new_content, count = re.subn(pattern, replacement, content, flags=re.MULTILINE)
    changes += count
    
    return new_content, changes

def migrate_log_statements(content: str) -> Tuple[str, int]:
    """Migrate log statements to structured format."""
    changes = 0
    
    # Pattern for % formatting
    pattern1 = r'logger\.(debug|info|warning|error)\("([^"]+)%s([^"]*)",\s*([^)]+)\)'
    
    def replace_percent(match):
        level = match.group(1)
        prefix = match.group(2)
        suffix = match.group(3)
        args = match.group(4)
        
        # Simple case: single argument
        if ',' not in args:
            var_name = args.strip()
            return f'logger.{level}("{prefix}{suffix}", value={var_name})'
        
        return match.group(0)  # Keep complex cases for manual review
    
    new_content, count = re.subn(pattern1, replace_percent, content)
    changes += count
    
    # Pattern for f-strings
    pattern2 = r'logger\.(debug|info|warning|error)\(f"([^"]+)\{([^}]+)\}([^"]*)"'
    
    def replace_fstring(match):
        level = match.group(1)
        prefix = match.group(2)
        var = match.group(3)
        suffix = match.group(4)
        
        return f'logger.{level}("{prefix}{suffix}", {var}={var})'
    
    new_content, count = re.subn(pattern2, replace_fstring, new_content)
    changes += count
    
    return new_content, changes

def migrate_file(file_path: Path) -> int:
    """Migrate a single file."""
    content = file_path.read_text()
    original = content
    
    # Apply migrations
    content, import_changes = migrate_imports(content)
    content, statement_changes = migrate_log_statements(content)
    
    total_changes = import_changes + statement_changes
    
    if total_changes > 0:
        # Create backup
        backup_path = file_path.with_suffix('.py.bak')
        backup_path.write_text(original)
        
        # Write migrated content
        file_path.write_text(content)
        
        print(f"✓ {file_path}: {total_changes} changes")
    
    return total_changes

def main():
    """Run migration."""
    src_dir = "src"
    
    print("🔄 Starting logging migration v4 → v5\n")
    
    files = find_python_files(src_dir)
    total_changes = 0
    
    for file_path in files:
        try:
            changes = migrate_file(file_path)
            total_changes += changes
        except Exception as e:
            print(f"❌ Error processing {file_path}: {e}")
    
    print(f"\n✅ Migration complete: {total_changes} changes in {len(files)} files")
    print("\n⚠️  Please review the changes and test thoroughly!")
    print("💡 Backup files created with .bak extension")

if __name__ == "__main__":
    main()
```

## Migration from v3 to v5

If migrating directly from v3, follow these additional steps:

### Additional Changes from v3

1. **Remove custom formatters** - v5 handles formatting automatically
2. **Remove log parsers** - v5 uses structured JSON
3. **Update log analysis tools** - Use JSON queries instead of regex

### v3 Specific Updates

```python
# v3: Custom formatter
class CustomFormatter(logging.Formatter):
    def format(self, record):
        # Custom formatting logic
        pass

# v5: Use structured logging instead
logger.info("Event occurred", custom_field="value")
```

## Testing Your Migration

### 1. Verify Configuration

```python
from src.core.logging import LogConfig

# Check current configuration
config = LogConfig()
print(config.dict())
```

### 2. Test PII Redaction

```python
from src.core.logging import get_logger

logger = get_logger("test")

# Test PII redaction
logger.info("Test PII", email="test@example.com", ip="192.168.1.1")
# Should show redacted values in output
```

### 3. Verify Audit Logging

```python
from src.core.logging.audit import log_audit_event, AuditEventType

# Test audit event
log_audit_event(
    event_type=AuditEventType.LOGIN_SUCCESS,
    user_id="test_user"
)
```

### 4. Check File Output

```bash
# Verify log files are being created
ls -la /var/log/app/

# Check log format
tail -f /var/log/app/backend.log | jq '.'
```

## Rollback Plan

If you need to rollback:

1. **Restore backup files**
   ```bash
   find src -name "*.py.bak" -exec sh -c 'mv "$1" "${1%.bak}"' _ {} \;
   ```

2. **Revert dependencies**
   ```bash
   git checkout -- requirements.txt
   pip install -r requirements.txt
   ```

3. **Restore configuration**
   ```bash
   git checkout -- .env
   ```

## Common Migration Issues

### Issue: Import Errors

```python
# Error: ModuleNotFoundError: No module named 'src.core.logging'

# Solution: Ensure PYTHONPATH includes project root
export PYTHONPATH=/path/to/project:$PYTHONPATH
```

### Issue: Missing Context

```python
# Error: Logger missing request context

# Solution: Add middleware to set context
from src.core.context import set_request_context

set_request_context(
    request_id=request.headers.get("X-Request-ID"),
    tenant_id=request.headers.get("X-Tenant-ID")
)
```

### Issue: Performance Degradation

```python
# If experiencing slower performance:

# 1. Disable caller info in production
LOG_ADD_CALLER_INFO=false

# 2. Increase log level
LOG_LEVEL=WARNING

# 3. Disable PII filtering if not needed
LOG_ENABLE_PII_FILTERING=false
```

## Feature Comparison

| Feature | v3 | v4 | v5 |
|---------|----|----|-------|
| Structured Logging | ❌ | ✅ JSON | ✅ Structlog |
| PII Redaction | ❌ | ❌ | ✅ Automatic |
| GDPR Compliance | ❌ | Partial | ✅ Full |
| Audit Logging | Custom | Custom | ✅ Built-in |
| Console Formatting | Basic | JSON | ✅ Rich |
| Context Injection | ❌ | Manual | ✅ Automatic |
| Log Rotation | External | Built-in | ✅ Enhanced |
| Performance | Good | Good | ✅ Optimized |

## Support

If you encounter issues during migration:

1. Check the [Troubleshooting Guide](./troubleshooting.md)
2. Review the [API Reference](./api-reference.md)
3. Contact the development team

---

**Migration Guide Version**: 1.0  
**Last Updated**: 2024-01-20  
**Target Version**: v5.0.0