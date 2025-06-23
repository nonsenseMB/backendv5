# Logging Configuration Guide

## Overview

The nAI Backend v5 logging system offers extensive configuration options through environment variables, configuration files, and programmatic setup. This guide covers all configuration aspects to help you optimize logging for your specific needs.

## Configuration Methods

### 1. Environment Variables (Recommended)

The simplest way to configure logging is through environment variables with the `LOG_` prefix.

```bash
# .env file
LOG_LEVEL=INFO
LOG_FORMAT=console
LOG_FILE_PATH=/var/log/app/backend.log
LOG_RETENTION_DAYS=90
LOG_ENABLE_PII_FILTERING=true
```

### 2. Configuration Object

For programmatic control, use the `LogConfig` class:

```python
from src.core.logging import configure_logging, LogConfig, LogLevel, LogFormat

config = LogConfig(
    level=LogLevel.DEBUG,
    format=LogFormat.CONSOLE,
    log_file_path="/custom/path/app.log",
    log_retention_days=180,
    enable_pii_filtering=True
)

configure_logging(config)
```

### 3. Runtime Reconfiguration

Change logging configuration at runtime:

```python
from src.core.logging import get_logger, configure_logging, LogConfig

# Initial configuration
configure_logging()

# Later, reconfigure for debugging
debug_config = LogConfig(level="DEBUG", format="console")
configure_logging(debug_config)

# Existing loggers will use new configuration
logger = get_logger(__name__)
logger.debug("Now visible!")
```

## Complete Configuration Reference

### Core Settings

| Environment Variable | Type | Default | Description |
|---------------------|------|---------|-------------|
| `LOG_LEVEL` | string | `INFO` | Minimum log level: `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL` |
| `LOG_FORMAT` | string | `json` | Output format: `json` for structured logs, `console` for human-readable |
| `LOG_FILE_PATH` | string | `/var/log/app/backend.log` | Path for log file output. Set empty to disable file logging |
| `LOG_ADD_TIMESTAMP` | boolean | `true` | Add ISO timestamp to all log entries |
| `LOG_ADD_CALLER_INFO` | boolean | `true` | Add source file, line number, and function name |
| `LOG_ADD_THREAD_INFO` | boolean | `false` | Add thread/process information (useful for debugging concurrency) |

### GDPR & Privacy Settings

| Environment Variable | Type | Default | Description |
|---------------------|------|---------|-------------|
| `LOG_ENABLE_PII_FILTERING` | boolean | `true` | Enable automatic PII detection and redaction |
| `LOG_RETENTION_DAYS` | integer | `90` | Days to retain logs before automatic deletion |
| `LOG_ENABLE_TAMPER_PROTECTION` | boolean | `true` | Enable cryptographic signing of logs |
| `LOG_PII_HASH_ALGORITHM` | string | `sha256` | Algorithm for PII pseudonymization |
| `LOG_PII_HASH_SALT` | string | - | Salt for PII hashing (auto-generated if not set) |

### Performance Settings

| Environment Variable | Type | Default | Description |
|---------------------|------|---------|-------------|
| `LOG_BUFFER_SIZE` | integer | `1000` | Number of log entries to buffer before flush |
| `LOG_FLUSH_INTERVAL` | integer | `1` | Seconds between automatic flushes |
| `LOG_MAX_FILE_SIZE_MB` | integer | `100` | Maximum log file size before rotation |
| `LOG_BACKUP_COUNT` | integer | `10` | Number of rotated log files to keep |
| `LOG_COMPRESSION` | boolean | `false` | Compress rotated log files |

### Console Output Settings

| Environment Variable | Type | Default | Description |
|---------------------|------|---------|-------------|
| `LOG_CONSOLE_COLORS` | boolean | `true` | Enable colored output in console format |
| `LOG_CONSOLE_WIDTH` | integer | `120` | Maximum width for console output |
| `LOG_CONSOLE_SHOW_PATH` | boolean | `true` | Show file path in console output |
| `LOG_CONSOLE_SHOW_LOCALS` | boolean | `false` | Show local variables in stack traces |

## Environment-Specific Configurations

### Development Configuration

Optimize for debugging and readability:

```bash
# .env.development
LOG_LEVEL=DEBUG
LOG_FORMAT=console
LOG_FILE_PATH=./logs/dev.log
LOG_RETENTION_DAYS=7
LOG_ENABLE_PII_FILTERING=true
LOG_ADD_CALLER_INFO=true
LOG_CONSOLE_COLORS=true
LOG_CONSOLE_SHOW_LOCALS=true
```

### Production Configuration

Optimize for performance and compliance:

```bash
# .env.production
LOG_LEVEL=INFO
LOG_FORMAT=json
LOG_FILE_PATH=/var/log/nai/backend.log
LOG_RETENTION_DAYS=90
LOG_ENABLE_PII_FILTERING=true
LOG_ENABLE_TAMPER_PROTECTION=true
LOG_MAX_FILE_SIZE_MB=500
LOG_BACKUP_COUNT=30
LOG_COMPRESSION=true
```

### Testing Configuration

Minimal logging for test suites:

```bash
# .env.test
LOG_LEVEL=WARNING
LOG_FORMAT=json
LOG_FILE_PATH=  # Empty to disable file logging
LOG_ENABLE_PII_FILTERING=false  # Speed up tests
LOG_ADD_TIMESTAMP=false
LOG_ADD_CALLER_INFO=false
```

### Docker Configuration

Container-friendly settings:

```yaml
# docker-compose.yml
services:
  backend:
    environment:
      - LOG_LEVEL=INFO
      - LOG_FORMAT=json
      - LOG_FILE_PATH=/logs/backend.log  # Mount volume here
      - LOG_RETENTION_DAYS=30
      - LOG_CONSOLE_COLORS=false  # Disable for container logs
    volumes:
      - ./logs:/logs
```

## Advanced Configuration Patterns

### Multi-Tenant Configuration

Configure logging per tenant:

```python
from src.core.logging import configure_logging, LogConfig
from typing import Dict

class TenantLogConfig:
    """Manage per-tenant logging configuration."""
    
    def __init__(self):
        self.configs: Dict[str, LogConfig] = {}
    
    def configure_for_tenant(self, tenant_id: str):
        """Apply tenant-specific logging configuration."""
        if tenant_id not in self.configs:
            # Load tenant config from database
            tenant_settings = load_tenant_settings(tenant_id)
            
            self.configs[tenant_id] = LogConfig(
                level=tenant_settings.get("log_level", "INFO"),
                log_file_path=f"/var/log/nai/{tenant_id}/backend.log",
                log_retention_days=tenant_settings.get("retention_days", 90),
                enable_pii_filtering=tenant_settings.get("pii_filtering", True)
            )
        
        configure_logging(self.configs[tenant_id])

# Usage in middleware
tenant_config = TenantLogConfig()

@app.middleware("http")
async def tenant_logging_middleware(request: Request, call_next):
    tenant_id = request.headers.get("X-Tenant-ID")
    if tenant_id:
        tenant_config.configure_for_tenant(tenant_id)
    
    return await call_next(request)
```

### Dynamic Log Level Control

Change log levels without restart:

```python
from src.core.logging import get_logger
import signal
import os

logger = get_logger(__name__)

class DynamicLogLevel:
    """Allow runtime log level changes via signals."""
    
    def __init__(self):
        signal.signal(signal.SIGUSR1, self.increase_verbosity)
        signal.signal(signal.SIGUSR2, self.decrease_verbosity)
        self.levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        self.current_index = 1  # Start at INFO
    
    def increase_verbosity(self, signum, frame):
        """Increase logging verbosity (lower level)."""
        if self.current_index > 0:
            self.current_index -= 1
            self.apply_level()
    
    def decrease_verbosity(self, signum, frame):
        """Decrease logging verbosity (higher level)."""
        if self.current_index < len(self.levels) - 1:
            self.current_index += 1
            self.apply_level()
    
    def apply_level(self):
        """Apply new log level."""
        new_level = self.levels[self.current_index]
        os.environ["LOG_LEVEL"] = new_level
        configure_logging()  # Reconfigure
        logger.info(f"Log level changed to {new_level}")

# Initialize
dynamic_level = DynamicLogLevel()

# Change levels with:
# kill -USR1 <pid>  # More verbose
# kill -USR2 <pid>  # Less verbose
```

### Conditional Logging

Configure logging based on conditions:

```python
from src.core.logging import configure_logging, LogConfig
import socket

def configure_conditional_logging():
    """Configure logging based on environment conditions."""
    hostname = socket.gethostname()
    
    # Different configs for different servers
    if "prod" in hostname:
        config = LogConfig(
            level="WARNING",
            format="json",
            log_file_path="/var/log/nai/backend.log"
        )
    elif "staging" in hostname:
        config = LogConfig(
            level="INFO",
            format="json",
            log_file_path="/var/log/nai/backend-staging.log"
        )
    else:  # Development
        config = LogConfig(
            level="DEBUG",
            format="console",
            log_file_path="./logs/dev.log"
        )
    
    # Apply special rules
    if os.getenv("ENABLE_AUDIT_MODE"):
        config.level = "DEBUG"
        config.add_caller_info = True
        config.enable_tamper_protection = True
    
    configure_logging(config)
```

### Log Routing

Route different log types to different outputs:

```python
import logging
from logging.handlers import RotatingFileHandler

def configure_log_routing():
    """Route different log types to different files."""
    
    # Main application logs
    app_handler = RotatingFileHandler(
        "/var/log/nai/app.log",
        maxBytes=100*1024*1024,
        backupCount=10
    )
    app_handler.setLevel(logging.INFO)
    
    # Audit logs (separate file)
    audit_handler = RotatingFileHandler(
        "/var/log/nai/audit.log",
        maxBytes=50*1024*1024,
        backupCount=30  # Keep longer
    )
    audit_handler.setLevel(logging.INFO)
    
    # Error logs (separate file)
    error_handler = RotatingFileHandler(
        "/var/log/nai/errors.log",
        maxBytes=50*1024*1024,
        backupCount=20
    )
    error_handler.setLevel(logging.ERROR)
    
    # Configure loggers
    logging.getLogger("src.api").addHandler(app_handler)
    logging.getLogger("src.core.audit").addHandler(audit_handler)
    logging.getLogger().addHandler(error_handler)  # Root logger for all errors
```

## Configuration Validation

### Startup Validation

Validate configuration on startup:

```python
from src.core.logging import LogConfig
from pathlib import Path
import sys

def validate_log_configuration():
    """Validate logging configuration on startup."""
    try:
        config = LogConfig()
        
        # Check file path is writable
        if config.log_file_path:
            log_path = Path(config.log_file_path)
            log_dir = log_path.parent
            
            if not log_dir.exists():
                print(f"Creating log directory: {log_dir}")
                log_dir.mkdir(parents=True, exist_ok=True)
            
            if not os.access(log_dir, os.W_OK):
                raise PermissionError(f"Cannot write to log directory: {log_dir}")
        
        # Validate retention days
        if config.log_retention_days < 1:
            raise ValueError("LOG_RETENTION_DAYS must be at least 1")
        
        if config.log_retention_days > 3650:  # 10 years
            print("WARNING: Very long retention period configured")
        
        # Test configuration
        configure_logging(config)
        logger = get_logger("config_test")
        logger.info("Configuration test successful")
        
    except Exception as e:
        print(f"ERROR: Invalid logging configuration: {e}")
        sys.exit(1)

# Run on startup
if __name__ == "__main__":
    validate_log_configuration()
```

### Health Check Endpoint

Monitor logging system health:

```python
from fastapi import APIRouter
from pathlib import Path
import os

router = APIRouter()

@router.get("/health/logging")
async def logging_health():
    """Check logging system health."""
    health = {
        "status": "healthy",
        "checks": {}
    }
    
    # Check log file access
    try:
        log_path = Path(os.getenv("LOG_FILE_PATH", "/var/log/app/backend.log"))
        if log_path.exists():
            stats = log_path.stat()
            health["checks"]["file_access"] = {
                "status": "ok",
                "size_mb": stats.st_size / (1024 * 1024),
                "writable": os.access(log_path, os.W_OK)
            }
        else:
            health["checks"]["file_access"] = {
                "status": "warning",
                "message": "Log file does not exist yet"
            }
    except Exception as e:
        health["checks"]["file_access"] = {
            "status": "error",
            "error": str(e)
        }
        health["status"] = "degraded"
    
    # Check disk space
    try:
        stat = os.statvfs(log_path.parent)
        free_gb = (stat.f_bavail * stat.f_frsize) / (1024**3)
        health["checks"]["disk_space"] = {
            "status": "ok" if free_gb > 1 else "warning",
            "free_gb": round(free_gb, 2)
        }
    except Exception as e:
        health["checks"]["disk_space"] = {
            "status": "error",
            "error": str(e)
        }
    
    return health
```

## Troubleshooting Configuration Issues

### Common Problems

1. **Logs not appearing**
   ```bash
   # Check configuration
   python -c "from src.core.logging import LogConfig; print(LogConfig().dict())"
   
   # Verify file permissions
   ls -la /var/log/app/
   ```

2. **Wrong format in production**
   ```bash
   # Force JSON format
   export LOG_FORMAT=json
   
   # Verify
   echo $LOG_FORMAT
   ```

3. **PII not being redacted**
   ```bash
   # Ensure filtering is enabled
   export LOG_ENABLE_PII_FILTERING=true
   
   # Test
   python -c "from src.core.logging import get_logger; get_logger().info('test@example.com')"
   ```

### Configuration Debugging

Enable configuration debugging:

```python
import os
os.environ["LOG_CONFIG_DEBUG"] = "true"

from src.core.logging import configure_logging
configure_logging()  # Will print configuration details
```

## Best Practices

### 1. Use Environment-Specific Files

```bash
# Load environment-specific config
export ENV=production
source .env.$ENV
```

### 2. Validate Early

```python
# In main.py
from src.core.logging import configure_logging

try:
    configure_logging()
except Exception as e:
    print(f"Failed to configure logging: {e}")
    sys.exit(1)
```

### 3. Document Custom Settings

```yaml
# logging-config.yml
production:
  level: INFO
  format: json
  retention_days: 90
  custom_settings:
    audit_logs_separate: true
    performance_tracking: true
    
development:
  level: DEBUG
  format: console
  retention_days: 7
  custom_settings:
    show_sql_queries: true
    profile_requests: true
```

### 4. Monitor Configuration

```python
# Log configuration changes
@app.on_event("startup")
async def log_configuration():
    config = LogConfig()
    logger.info(
        "Logging configured",
        level=config.level,
        format=config.format,
        pii_filtering=config.enable_pii_filtering,
        retention_days=config.log_retention_days
    )
```

---

**Guide Version**: 1.0  
**Last Updated**: 2024-01-20  
**Configuration Schema Version**: v5.0.0