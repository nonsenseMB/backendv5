# Logging Troubleshooting Guide

## Overview

This guide helps you diagnose and resolve common issues with the nAI Backend v5 logging system. Each issue includes symptoms, diagnostic steps, and solutions.

## Quick Diagnostics

### Health Check Script

Run this script to check your logging setup:

```python
#!/usr/bin/env python3
"""Logging system diagnostic script."""

import os
import sys
from pathlib import Path

def check_logging_health():
    """Run logging system diagnostics."""
    print("🔍 Logging System Diagnostics\n")
    
    issues = []
    
    # Check environment variables
    print("1. Environment Variables:")
    log_vars = {k: v for k, v in os.environ.items() if k.startswith("LOG_")}
    if not log_vars:
        print("   ⚠️  No LOG_* environment variables found")
        issues.append("No logging configuration in environment")
    else:
        for key, value in log_vars.items():
            print(f"   ✓ {key}={value}")
    
    # Check log file path
    print("\n2. Log File Access:")
    log_path = os.getenv("LOG_FILE_PATH", "/var/log/app/backend.log")
    log_file = Path(log_path)
    log_dir = log_file.parent
    
    if log_dir.exists():
        print(f"   ✓ Log directory exists: {log_dir}")
        if os.access(log_dir, os.W_OK):
            print(f"   ✓ Write permission: OK")
        else:
            print(f"   ❌ No write permission to {log_dir}")
            issues.append(f"Cannot write to log directory: {log_dir}")
    else:
        print(f"   ⚠️  Log directory does not exist: {log_dir}")
        issues.append(f"Log directory missing: {log_dir}")
    
    # Check disk space
    print("\n3. Disk Space:")
    try:
        stat = os.statvfs(log_dir if log_dir.exists() else "/")
        free_gb = (stat.f_bavail * stat.f_frsize) / (1024**3)
        print(f"   {'✓' if free_gb > 1 else '⚠️'} Free space: {free_gb:.2f} GB")
        if free_gb < 1:
            issues.append("Low disk space for logging")
    except Exception as e:
        print(f"   ❌ Could not check disk space: {e}")
    
    # Test logging
    print("\n4. Test Logging:")
    try:
        from src.core.logging import get_logger
        logger = get_logger("diagnostic")
        logger.info("Test message", test=True)
        print("   ✓ Logging works")
    except Exception as e:
        print(f"   ❌ Logging failed: {e}")
        issues.append(f"Logging error: {e}")
    
    # Summary
    print("\n" + "="*50)
    if issues:
        print("❌ Issues found:")
        for issue in issues:
            print(f"   - {issue}")
        return 1
    else:
        print("✅ All checks passed!")
        return 0

if __name__ == "__main__":
    sys.exit(check_logging_health())
```

## Common Issues and Solutions

### Issue: No Logs Appearing

**Symptoms:**
- Application runs but no log output
- Log files empty or not created
- No console output

**Diagnosis:**
```bash
# Check log level
echo $LOG_LEVEL

# Check if logging is configured
python -c "from src.core.logging import LogConfig; print(LogConfig().dict())"

# Test basic logging
python -c "from src.core.logging import get_logger; get_logger().error('TEST ERROR')"
```

**Solutions:**

1. **Log level too high:**
   ```bash
   # Lower log level
   export LOG_LEVEL=DEBUG
   ```

2. **Logging not initialized:**
   ```python
   # In main.py
   from src.core.logging import configure_logging
   
   # Must be called before any logging
   configure_logging()
   ```

3. **File permissions:**
   ```bash
   # Fix permissions
   sudo mkdir -p /var/log/app
   sudo chown $USER:$USER /var/log/app
   chmod 755 /var/log/app
   ```

### Issue: PII Not Being Redacted

**Symptoms:**
- Email addresses, IPs visible in logs
- `_pii_redacted` field missing or shows zeros
- Sensitive data exposed

**Diagnosis:**
```python
# Check if PII filtering is enabled
from src.core.logging import LogConfig
config = LogConfig()
print(f"PII Filtering: {config.enable_pii_filtering}")

# Test PII redaction
from src.core.logging import get_logger
logger = get_logger("test")
logger.info("Test email", email="test@example.com")
# Should show: email="[EMAIL]:hash"
```

**Solutions:**

1. **Enable PII filtering:**
   ```bash
   export LOG_ENABLE_PII_FILTERING=true
   ```

2. **Fix filter initialization:**
   ```python
   # Ensure filters are loaded
   from src.core.logging import configure_logging
   configure_logging()  # Re-initialize
   ```

3. **Add custom patterns:**
   ```python
   from src.core.logging.filters import PIIRedactionFilter, RedactionRule
   import re
   
   # Add custom pattern
   filter = PIIRedactionFilter()
   filter.add_rule(RedactionRule(
       name="custom_id",
       pattern=re.compile(r"ID-\d{6}"),
       replacement="[ID]"
   ))
   ```

### Issue: Console Output Unreadable

**Symptoms:**
- JSON logs in development
- ANSI color codes in log files
- Nested/escaped output

**Diagnosis:**
```bash
# Check format setting
echo $LOG_FORMAT

# Check terminal support
python -c "import sys; print(f'TTY: {sys.stdout.isatty()}')"
```

**Solutions:**

1. **Set console format:**
   ```bash
   export LOG_FORMAT=console
   ```

2. **Fix ANSI codes in files:**
   ```python
   # Ensure file handler uses JSON
   from src.core.logging import configure_logging, LogConfig
   
   config = LogConfig(
       format="console",  # For terminal
       # File handler automatically uses JSON
   )
   configure_logging(config)
   ```

3. **Disable colors if needed:**
   ```bash
   export LOG_CONSOLE_COLORS=false
   ```

### Issue: High Memory Usage

**Symptoms:**
- Memory grows over time
- OOM errors
- Slow logging performance

**Diagnosis:**
```python
# Check buffer size
import os
print(f"Buffer size: {os.getenv('LOG_BUFFER_SIZE', '1000')}")

# Monitor memory
import psutil
import os
process = psutil.Process(os.getpid())
print(f"Memory usage: {process.memory_info().rss / 1024 / 1024:.2f} MB")
```

**Solutions:**

1. **Reduce buffer size:**
   ```bash
   export LOG_BUFFER_SIZE=100
   export LOG_FLUSH_INTERVAL=0.5
   ```

2. **Disable caller info:**
   ```bash
   export LOG_ADD_CALLER_INFO=false
   export LOG_ADD_THREAD_INFO=false
   ```

3. **Increase log level:**
   ```bash
   export LOG_LEVEL=WARNING  # Reduce log volume
   ```

### Issue: Log Files Growing Too Large

**Symptoms:**
- Disk space filling up
- Large log files (>1GB)
- Old logs not being deleted

**Diagnosis:**
```bash
# Check log file sizes
ls -lah /var/log/app/*.log*

# Check rotation settings
python -c "import os; print(f'Max size: {os.getenv(\"LOG_MAX_FILE_SIZE_MB\", 100)}MB')"

# Check retention
python -c "from src.core.logging import LogConfig; print(f'Retention: {LogConfig().log_retention_days} days')"
```

**Solutions:**

1. **Configure rotation:**
   ```bash
   export LOG_MAX_FILE_SIZE_MB=100
   export LOG_BACKUP_COUNT=10
   export LOG_COMPRESSION=true
   ```

2. **Manual cleanup:**
   ```python
   from src.core.logging.retention import LogRetentionManager
   
   manager = LogRetentionManager(
       log_directory="/var/log/app",
       retention_days=30
   )
   
   # Dry run first
   result = await manager.cleanup_old_logs(dry_run=True)
   print(f"Would delete: {result['files_to_delete']} files")
   
   # Actual cleanup
   await manager.cleanup_old_logs()
   ```

3. **Size-based cleanup:**
   ```python
   # Keep total size under 1GB
   await manager.cleanup_by_size(max_size_mb=1000)
   ```

### Issue: Performance Degradation

**Symptoms:**
- Slow response times
- High CPU usage during logging
- Application hangs

**Diagnosis:**
```python
# Profile logging performance
import time
from src.core.logging import get_logger

logger = get_logger("perf_test")

# Time logging operations
start = time.time()
for i in range(1000):
    logger.info("Test message", index=i, data={"nested": "value"})
duration = time.time() - start
print(f"1000 logs took: {duration:.2f}s ({duration/1000*1000:.2f}ms per log)")
```

**Solutions:**

1. **Async logging:**
   ```python
   # Use async file handler
   import asyncio
   from concurrent.futures import ThreadPoolExecutor
   
   executor = ThreadPoolExecutor(max_workers=2)
   
   class AsyncLogHandler:
       def emit(self, record):
           executor.submit(self._emit_async, record)
       
       def _emit_async(self, record):
           # Actual file write
           pass
   ```

2. **Reduce processing:**
   ```bash
   # Disable expensive features
   export LOG_ADD_CALLER_INFO=false
   export LOG_ENABLE_PII_FILTERING=false  # Only if safe
   ```

3. **Batch logging:**
   ```python
   from src.core.logging import get_logger
   
   logger = get_logger("batch")
   
   # Collect logs
   batch = []
   for item in large_dataset:
       batch.append({"item": item.id, "status": "processed"})
       
       # Log in batches
       if len(batch) >= 100:
           logger.info("Batch processed", items=batch)
           batch = []
   ```

### Issue: Missing Request Context

**Symptoms:**
- No tenant_id, request_id in logs
- Cannot correlate requests
- Missing user context

**Diagnosis:**
```python
# Check context
from src.core.context import get_request_context
context = get_request_context()
print(f"Current context: {context}")
```

**Solutions:**

1. **Set context in middleware:**
   ```python
   from src.core.context import set_request_context
   
   @app.middleware("http")
   async def logging_context_middleware(request: Request, call_next):
       set_request_context(
           request_id=request.headers.get("X-Request-ID", str(uuid.uuid4())),
           tenant_id=request.headers.get("X-Tenant-ID"),
           user_id=getattr(request.state, "user_id", None)
       )
       
       response = await call_next(request)
       return response
   ```

2. **Manual context:**
   ```python
   from src.core.logging import get_logger
   
   # Bind context to logger
   logger = get_logger(__name__).bind(
       request_id="req_123",
       tenant_id="tenant_456"
   )
   ```

### Issue: Duplicate Log Entries

**Symptoms:**
- Same message appears multiple times
- Duplicate handlers
- Repeated initialization

**Diagnosis:**
```python
import logging

# Check handlers
root_logger = logging.getLogger()
print(f"Root handlers: {len(root_logger.handlers)}")
for handler in root_logger.handlers:
    print(f"  - {type(handler).__name__}")
```

**Solutions:**

1. **Clear existing handlers:**
   ```python
   import logging
   
   # Clear before configuring
   root_logger = logging.getLogger()
   for handler in root_logger.handlers[:]:
       root_logger.removeHandler(handler)
   
   # Now configure
   configure_logging()
   ```

2. **Use singleton pattern:**
   ```python
   # Ensure single configuration
   _configured = False
   
   def configure_once():
       global _configured
       if not _configured:
           configure_logging()
           _configured = True
   ```

## Performance Optimization

### Logging Benchmarks

```python
"""Benchmark different logging configurations."""

import time
from src.core.logging import get_logger, configure_logging, LogConfig

def benchmark_config(name: str, config: LogConfig, iterations: int = 10000):
    """Benchmark a logging configuration."""
    configure_logging(config)
    logger = get_logger("benchmark")
    
    start = time.time()
    for i in range(iterations):
        logger.info(
            "Benchmark message",
            index=i,
            data={"key": "value", "number": 42},
            email="test@example.com"  # Test PII redaction
        )
    duration = time.time() - start
    
    print(f"{name}: {duration:.2f}s ({iterations/duration:.0f} logs/sec)")

# Test configurations
configs = {
    "Minimal": LogConfig(
        level="INFO",
        format="json",
        add_timestamp=False,
        add_caller_info=False,
        enable_pii_filtering=False
    ),
    "Standard": LogConfig(
        level="INFO",
        format="json",
        add_timestamp=True,
        add_caller_info=False,
        enable_pii_filtering=True
    ),
    "Full": LogConfig(
        level="DEBUG",
        format="console",
        add_timestamp=True,
        add_caller_info=True,
        enable_pii_filtering=True
    )
}

for name, config in configs.items():
    benchmark_config(name, config)
```

### Memory Profiling

```python
"""Profile memory usage of logging system."""

import tracemalloc
from src.core.logging import get_logger

# Start tracing
tracemalloc.start()

# Create logger and log messages
logger = get_logger("memory_test")
baseline = tracemalloc.take_snapshot()

# Log many messages
for i in range(10000):
    logger.info(f"Message {i}", data={"index": i})

# Take snapshot
snapshot = tracemalloc.take_snapshot()

# Compare
top_stats = snapshot.compare_to(baseline, 'lineno')
print("[ Top 10 memory consumers ]")
for stat in top_stats[:10]:
    print(stat)
```

## Debug Mode

### Enable Verbose Debugging

```python
# debug_logging.py
"""Enable verbose logging debug mode."""

import logging
import structlog

def enable_debug_mode():
    """Enable verbose debugging for logging system."""
    # Set all loggers to DEBUG
    logging.getLogger().setLevel(logging.DEBUG)
    
    # Add debug processor
    def debug_processor(logger, method_name, event_dict):
        """Add debug information to all logs."""
        import inspect
        
        # Add call stack
        stack = inspect.stack()[8:10]  # Skip logging internals
        event_dict['_debug_stack'] = [
            f"{frame.filename}:{frame.lineno} in {frame.function}"
            for frame in stack
        ]
        
        # Add logger internals
        event_dict['_debug_logger'] = logger.name
        event_dict['_debug_method'] = method_name
        
        return event_dict
    
    # Reconfigure with debug processor
    structlog.configure(
        processors=[
            debug_processor,
            structlog.stdlib.add_log_level,
            structlog.dev.ConsoleRenderer()
        ]
    )
    
    print("🐛 Debug mode enabled")

# Usage
if __name__ == "__main__":
    enable_debug_mode()
    
    from src.core.logging import get_logger
    logger = get_logger("debug_test")
    logger.info("Debug test message")
```

## Recovery Procedures

### Corrupted Log Files

```python
"""Recover from corrupted log files."""

import json
from pathlib import Path

def recover_log_file(corrupted_file: Path, output_file: Path):
    """Attempt to recover readable entries from corrupted log file."""
    recovered = []
    errors = []
    
    with open(corrupted_file, 'r', errors='ignore') as f:
        for line_no, line in enumerate(f, 1):
            if not line.strip():
                continue
                
            try:
                # Try to parse as JSON
                entry = json.loads(line)
                recovered.append(entry)
            except json.JSONDecodeError:
                # Try to extract partial data
                try:
                    # Look for timestamp
                    if '"timestamp"' in line:
                        errors.append({
                            "line": line_no,
                            "content": line[:100] + "...",
                            "error": "Invalid JSON"
                        })
                except Exception as e:
                    errors.append({
                        "line": line_no,
                        "error": str(e)
                    })
    
    # Write recovered entries
    with open(output_file, 'w') as f:
        for entry in recovered:
            f.write(json.dumps(entry) + '\n')
    
    print(f"Recovered {len(recovered)} entries")
    print(f"Failed to recover {len(errors)} entries")
    
    return recovered, errors
```

### Emergency Logging

```python
"""Fallback logging when main system fails."""

import sys
import datetime

class EmergencyLogger:
    """Minimal logger for critical failures."""
    
    def __init__(self, file_path: str = "/tmp/emergency.log"):
        self.file_path = file_path
    
    def log(self, level: str, message: str, **kwargs):
        """Write emergency log entry."""
        timestamp = datetime.datetime.utcnow().isoformat()
        
        try:
            with open(self.file_path, 'a') as f:
                entry = {
                    "timestamp": timestamp,
                    "level": level,
                    "message": message,
                    "data": kwargs
                }
                f.write(json.dumps(entry) + '\n')
                f.flush()
        except Exception as e:
            # Last resort - print to stderr
            print(f"[EMERGENCY] {timestamp} {level}: {message} {kwargs}", 
                  file=sys.stderr)
            print(f"[EMERGENCY] Logging failed: {e}", file=sys.stderr)

# Use when main logging fails
emergency = EmergencyLogger()

try:
    # Normal operation
    logger.info("Normal operation")
except Exception as e:
    emergency.log("CRITICAL", "Main logging failed", error=str(e))
```

## Monitoring and Alerts

### Log Monitoring Script

```bash
#!/bin/bash
# monitor_logs.sh - Monitor log health

LOG_DIR="/var/log/app"
ALERT_EMAIL="ops@example.com"

# Check log file growth
check_log_growth() {
    local file=$1
    local max_size_mb=$2
    
    if [ -f "$file" ]; then
        size_mb=$(du -m "$file" | cut -f1)
        if [ "$size_mb" -gt "$max_size_mb" ]; then
            echo "WARNING: $file is ${size_mb}MB (max: ${max_size_mb}MB)"
            return 1
        fi
    fi
    return 0
}

# Check error rate
check_error_rate() {
    local file=$1
    local max_errors_per_min=$2
    
    if [ -f "$file" ]; then
        recent_errors=$(grep -c '"level":"error"' "$file" | tail -1000)
        if [ "$recent_errors" -gt "$max_errors_per_min" ]; then
            echo "WARNING: High error rate: $recent_errors errors"
            return 1
        fi
    fi
    return 0
}

# Run checks
issues=""

if ! check_log_growth "$LOG_DIR/backend.log" 500; then
    issues+="Log file too large\n"
fi

if ! check_error_rate "$LOG_DIR/backend.log" 100; then
    issues+="High error rate\n"
fi

# Send alert if issues
if [ -n "$issues" ]; then
    echo -e "Log monitoring alert:\n$issues" | mail -s "Log Alert" $ALERT_EMAIL
fi
```

## Getting Help

### Diagnostic Information to Collect

When reporting logging issues, collect:

1. **Configuration:**
   ```bash
   python -c "from src.core.logging import LogConfig; print(LogConfig().dict())"
   ```

2. **Environment:**
   ```bash
   env | grep LOG_
   python --version
   pip list | grep structlog
   ```

3. **Sample logs:**
   ```bash
   tail -100 /var/log/app/backend.log
   ```

4. **Error messages:**
   ```bash
   journalctl -u your-service -n 100
   ```

### Support Channels

- GitHub Issues: [Report bugs](https://github.com/example/repo/issues)
- Documentation: [Full docs](https://docs.example.com)
- Community: [Discord/Slack](#)

---

**Guide Version**: 1.0  
**Last Updated**: 2024-01-20  
**Troubleshooting Database**: v5.0.0