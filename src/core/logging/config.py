"""Logging configuration for structured logging with structlog.

This module configures the logging system for the application with:
- Environment-based log levels
- JSON formatting for production
- Console formatting for development
- Custom logger factory
- Performance optimizations

Author: Mike Berndt <berndt.mike@gmail.com>
Date: 2025-06-20
"""

import logging
import os
import sys
from enum import Enum
from pathlib import Path
from typing import Any

import structlog
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class LogLevel(str, Enum):
    """Log levels supported by the application."""

    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class LogFormat(str, Enum):
    """Log output formats."""

    JSON = "json"
    CONSOLE = "console"


class LogConfig(BaseSettings):
    """Configuration for the logging system.

    This class reads configuration from environment variables with the prefix LOG_.
    For example:
    - LOG_LEVEL=DEBUG
    - LOG_FORMAT=console
    - LOG_ADD_TIMESTAMP=false

    Attributes
    ----------
        level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        format: Output format (json or console)
        add_timestamp: Whether to add timestamp to logs
        add_caller_info: Whether to add file/line information
        add_thread_info: Whether to add thread/process information

    """

    model_config = SettingsConfigDict(
        env_prefix="LOG_",
        case_sensitive=False,
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    level: LogLevel = Field(
        default=LogLevel.INFO, description="Minimum log level to output"
    )
    format: LogFormat = Field(
        default=LogFormat.JSON, description="Output format for logs"
    )
    add_timestamp: bool = Field(
        default=True, description="Add timestamp to log entries"
    )
    add_caller_info: bool = Field(
        default=True, description="Add source file and line number"
    )
    add_thread_info: bool = Field(
        default=False, description="Add thread/process information"
    )

    # GDPR/DSGVO Compliance Settings
    enable_pii_filtering: bool = Field(
        default=True, description="Enable automatic PII filtering for GDPR compliance"
    )
    log_retention_days: int = Field(
        default=90, description="Days to retain logs (GDPR requirement)"
    )
    enable_tamper_protection: bool = Field(
        default=True, description="Enable cryptographic log signing"
    )
    log_file_path: str = Field(
        default="/var/log/app/backend.log", description="Path for log files"
    )

    @field_validator("level", mode="before")
    @classmethod
    def validate_level(cls, v: Any) -> str:
        """Validate and convert log level to uppercase."""
        if isinstance(v, str):
            return v.upper()
        return v

    @field_validator("format", mode="before")
    @classmethod
    def validate_format_for_env(cls, v: Any) -> str:
        """Set format based on environment if not explicitly set."""
        if v is None or v == "":
            # Auto-detect based on environment
            env = os.getenv("ENVIRONMENT", "production").lower()
            return "console" if env in ("development", "dev", "local") else "json"
        return v


def _add_request_context(
    logger: Any, method_name: str, event_dict: dict[str, Any]
) -> dict[str, Any]:
    """Add request context (tenant_id, request_id, etc.) to log events."""
    try:
        from src.core.context import get_request_context

        context = get_request_context()
        if context:
            if context.tenant_id:
                event_dict["tenant_id"] = context.tenant_id
            if context.request_id:
                event_dict["request_id"] = context.request_id
            if context.user_id:
                event_dict["user_id"] = context.user_id
    except Exception:
        # Don't fail logging if context extraction fails
        pass
    return event_dict


def _create_processor_chain(config: LogConfig, use_console_renderer: bool = False) -> list:
    """Create the full processor chain based on configuration.
    
    Args:
    ----
        config: Logging configuration
        use_console_renderer: Whether to use console renderer (vs JSON)
        
    Returns:
    -------
        List of processors for structlog
        
    """
    processors = []
    
    # Add PII redaction filter as FIRST processor for GDPR compliance
    if config.enable_pii_filtering:
        from .filters import PIIRedactionFilter
        processors.append(PIIRedactionFilter())
    
    # Add timestamp if configured
    if config.add_timestamp:
        processors.append(structlog.processors.TimeStamper(fmt="iso"))
    
    # Add standard processors
    processors.extend(_add_custom_processors())
    
    # Add caller info if configured
    if config.add_caller_info:
        processors.append(
            structlog.processors.CallsiteParameterAdder(
                parameters=[
                    structlog.processors.CallsiteParameter.FILENAME,
                    structlog.processors.CallsiteParameter.LINENO,
                    structlog.processors.CallsiteParameter.FUNC_NAME,
                ]
            )
        )
    
    # Add thread info if configured
    if config.add_thread_info:
        processors.append(structlog.processors.add_thread_info)
    
    # Add final renderer
    if use_console_renderer and config.format == LogFormat.CONSOLE:
        try:
            from src.core.logging.console import RichConsoleRenderer
            processors.append(RichConsoleRenderer(
                show_path=True, 
                show_timestamp=True, 
                show_tenant=True
            ))
        except ImportError:
            processors.append(structlog.dev.ConsoleRenderer())
    else:
        processors.append(structlog.processors.JSONRenderer())
    
    return processors


def _add_custom_processors() -> list:
    """Create list of custom processors for structlog.

    Returns
    -------
        List of processor functions for structlog pipeline

    """
    return [
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.dev.set_exc_info,
        _add_request_context,  # Add our context injector
    ]


def _create_formatter_processor(format_type: LogFormat, is_file_handler: bool = False) -> Any:
    """Create appropriate formatter based on format type.

    Args:
    ----
        format_type: The desired output format
        is_file_handler: Whether this is for file output (always use JSON for files)

    Returns:
    -------
        Structlog processor for formatting

    """
    # Always use JSON for file handlers
    if is_file_handler or format_type == LogFormat.JSON:
        return structlog.processors.JSONRenderer()

    # Use Rich console renderer for development
    try:
        from src.core.logging.console import RichConsoleRenderer

        return RichConsoleRenderer(
            show_path=True, show_timestamp=True, show_tenant=True
        )
    except ImportError:
        # Fallback to default console renderer
        return structlog.dev.ConsoleRenderer(colors=sys.stderr.isatty(), pad_event=True)


def configure_logging(config: LogConfig | None = None) -> None:
    """Configure the logging system with structlog.

    This function sets up:
    - Standard library logging integration
    - Structlog configuration
    - Custom processors including PII redaction
    - Output formatting

    If no config is provided, it will read from environment variables.

    Args:
    ----
        config: Logging configuration. If None, reads from environment.

    """
    if config is None:
        config = LogConfig()

    # Remove all existing handlers first
    root_logger = logging.getLogger()
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)

    # Set root logger level
    root_logger.setLevel(config.level.value)

    # Create console handler with custom formatting
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(config.level.value)
    
    # Create console processors (with Rich formatting)
    console_processors = _create_processor_chain(config, use_console_renderer=True)
    
    # Create console formatter
    console_formatter = structlog.stdlib.ProcessorFormatter(
        processor=structlog.dev.ConsoleRenderer() if config.format == LogFormat.JSON else console_processors[-1],
        foreign_pre_chain=console_processors[:-1],
    )
    console_handler.setFormatter(console_formatter)
    root_logger.addHandler(console_handler)
    
    # Add file handler if log_file_path is configured
    if config.log_file_path:
        try:
            # Ensure directory exists
            log_path = Path(config.log_file_path)
            log_dir = log_path.parent
            log_dir.mkdir(parents=True, exist_ok=True)
            
            # Create file handler with rotation support
            from logging.handlers import RotatingFileHandler
            file_handler = RotatingFileHandler(
                filename=str(log_path),
                maxBytes=100 * 1024 * 1024,  # 100MB per file
                backupCount=10,  # Keep 10 backup files
                encoding='utf-8'
            )
            file_handler.setLevel(config.level.value)
            
            # Create file processors (always JSON for files)
            file_processors = _create_processor_chain(config, use_console_renderer=False)
            
            # Create file formatter
            file_formatter = structlog.stdlib.ProcessorFormatter(
                processor=structlog.processors.JSONRenderer(),
                foreign_pre_chain=file_processors[:-1],
            )
            file_handler.setFormatter(file_formatter)
            root_logger.addHandler(file_handler)
            
            print(f"📝 Logging to file: {config.log_file_path}")
        except Exception as e:
            print(f"⚠️  WARNING: Could not create log file at {config.log_file_path}: {e}")
            print("⚠️  Falling back to console-only logging")
    
    # Configure structlog
    structlog.configure(
        processors=console_processors if config.format == LogFormat.CONSOLE else file_processors,
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )
    
    # Log compliance status
    if config.enable_pii_filtering:
        print("🔒 PII filtering ENABLED for GDPR compliance")
    else:
        print("⚠️  WARNING: PII filtering DISABLED - potential GDPR violation!")


def get_logger(name: str | None = None, **kwargs: Any) -> structlog.BoundLogger:
    """Get a configured logger instance.

    This is a convenience function that returns a properly configured
    structlog logger with any additional context.

    Args:
    ----
        name: Logger name. If None, uses calling module name.
        **kwargs: Additional context to bind to the logger

    Returns:
    -------
        Configured structlog logger instance

    """
    logger = structlog.get_logger(name)

    if kwargs:
        logger = logger.bind(**kwargs)

    return logger


# Module-level logger for this module
logger = get_logger(__name__)
