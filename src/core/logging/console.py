"""Rich console formatter for beautiful structured logs.

This module provides a custom console renderer that integrates
Rich with structlog for beautiful, colored console output.
"""

from typing import Any

from rich.console import Console
from rich.traceback import Traceback

# Create a shared console instance
console = Console(stderr=True, force_terminal=True)


class RichConsoleRenderer:
    """Custom console renderer using Rich for beautiful output."""

    def __init__(
        self,
        show_path: bool = True,
        show_timestamp: bool = True,
        show_tenant: bool = True,
    ) -> None:
        """Initialize the Rich console renderer.

        Args:
        ----
            show_path: Whether to show file path and line number
            show_timestamp: Whether to show timestamp
            show_tenant: Whether to show tenant ID

        """
        self.show_path = show_path
        self.show_timestamp = show_timestamp
        self.show_tenant = show_tenant

        # Log level colors and icons
        self.level_styles = {
            "debug": ("dim cyan", "🔍"),
            "info": ("green", "ℹ️ "),
            "warning": ("yellow", "⚠️ "),
            "error": ("red bold", "❌"),
            "critical": ("red bold reverse", "🚨"),
        }

    def __call__(self, _: Any, __: str, event_dict: dict[str, Any]) -> str:
        """Render log event using Rich.

        Args:
        ----
            _: Logger (unused)
            __: Method name (unused)
            event_dict: Event dictionary from structlog

        Returns:
        -------
            Empty string (Rich prints directly to console)

        """
        # Extract standard fields
        level = event_dict.pop("level", "info").lower()
        msg = event_dict.pop("event", "")
        timestamp = event_dict.pop("timestamp", None)

        # Extract context fields
        logger_name = event_dict.pop("logger", None)
        # Handle both pathname and filename
        pathname = event_dict.pop("pathname", None) or event_dict.pop("filename", None)
        lineno = event_dict.pop("lineno", None)
        func_name = event_dict.pop("func_name", None)

        # Extract our custom fields
        request_id = event_dict.pop("request_id", None)
        tenant_id = event_dict.pop("tenant_id", None)
        user_id = event_dict.pop("user_id", None)

        # Special handling for request logs
        if "method" in event_dict and "path" in event_dict:
            self._render_request_log(event_dict, level, timestamp, tenant_id)
            return ""

        # Get style and icon for level
        style, icon = self.level_styles.get(level, ("white", "•"))

        # Build the main message
        output_parts = []

        # Timestamp
        if self.show_timestamp and timestamp:
            output_parts.append(f"[dim]{timestamp}[/dim]")

        # Level with icon
        output_parts.append(f"[{style}]{icon} {level.upper():>8}[/{style}]")

        # Logger name and location
        if self.show_path and logger_name:
            location_parts = [logger_name]
            if pathname and lineno:
                location_parts.append(f"{pathname}:{lineno}")
            if func_name:
                location_parts.append(f"in {func_name}()")
            output_parts.append(f"[dim blue]{' '.join(location_parts)}[/dim blue]")

        # Context IDs
        context_parts = []
        if self.show_tenant and tenant_id:
            context_parts.append(f"[cyan]tenant={tenant_id}[/cyan]")
        if request_id:
            context_parts.append(f"[dim]req={request_id[:8]}[/dim]")
        if user_id:
            context_parts.append(f"[dim]user={user_id}[/dim]")

        if context_parts:
            output_parts.append(" ".join(context_parts))

        # Main message
        console.print(" │ ".join(output_parts), end=" ")
        console.print(f"[bold]{msg}[/bold]")

        # Handle exceptions
        exc_info = event_dict.pop("exc_info", None)
        if exc_info:
            # If exc_info is True, get current exception info
            if exc_info is True:
                import sys

                exc_info = sys.exc_info()

            # Only render if we have actual exception info
            if isinstance(exc_info, tuple) and len(exc_info) >= 3 and exc_info[0]:
                tb = Traceback.from_exception(
                    exc_info[0],
                    exc_info[1],
                    exc_info[2],
                    show_locals=True,
                    width=console.width,
                )
                console.print(tb)

        # Additional fields
        if event_dict:
            self._render_extra_fields(event_dict, indent=2)

        return ""

    def _render_request_log(
        self,
        event_dict: dict[str, Any],
        level: str,
        timestamp: str | None,
        tenant_id: str | None,
    ) -> None:
        """Render HTTP request logs with special formatting."""
        method = event_dict.pop("method", "?")
        path = event_dict.pop("path", "?")
        status_code = event_dict.pop("status_code", None)
        duration_ms = event_dict.pop("duration_ms", None)

        # Determine status style
        if status_code:
            if status_code < 300:
                status_style = "green"
            elif status_code < 400:
                status_style = "yellow"
            elif status_code < 500:
                status_style = "orange1"
            else:
                status_style = "red"
        else:
            status_style = "dim"

        # Build compact request log
        parts = []

        if timestamp and self.show_timestamp:
            parts.append(f"[dim]{timestamp}[/dim]")

        # Method with color
        method_colors = {
            "GET": "green",
            "POST": "blue",
            "PUT": "yellow",
            "PATCH": "yellow",
            "DELETE": "red",
        }
        method_color = method_colors.get(method, "white")
        parts.append(f"[{method_color}]{method:>7}[/{method_color}]")

        # Path
        parts.append(f"[white]{path}[/white]")

        # Status code
        if status_code:
            parts.append(f"[{status_style}]{status_code}[/{status_style}]")

        # Duration
        if duration_ms:
            if duration_ms > 1000:
                duration_style = "red"
            elif duration_ms > 500:
                duration_style = "yellow"
            else:
                duration_style = "green"
            parts.append(f"[{duration_style}]{duration_ms:>6.1f}ms[/{duration_style}]")

        # Tenant
        if tenant_id and self.show_tenant:
            parts.append(f"[cyan]tenant={tenant_id}[/cyan]")

        console.print(" │ ".join(parts))

        # Show additional fields if any
        if event_dict:
            self._render_extra_fields(event_dict, indent=2)

    def _render_extra_fields(self, fields: dict[str, Any], indent: int = 0) -> None:
        """Render additional fields as a table."""
        if not fields:
            return

        # Skip internal structlog fields
        skip_fields = {"_record", "_from_structlog"}
        fields = {k: v for k, v in fields.items() if k not in skip_fields}

        if not fields:
            return

        # Create a simple indented display
        indent_str = " " * indent
        for key, value in fields.items():
            # Format value
            if isinstance(value, dict):
                console.print(f"{indent_str}[dim cyan]{key}:[/dim cyan]")
                self._render_extra_fields(value, indent + 2)
            elif isinstance(value, list | tuple):
                console.print(f"{indent_str}[dim cyan]{key}:[/dim cyan] {value}")
            else:
                console.print(f"{indent_str}[dim cyan]{key}:[/dim cyan] {value}")


def create_startup_banner() -> str:
    """Create ASCII art startup banner."""
    return """
[bold cyan]
    ███╗   ██╗ █████╗ ██╗    ██████╗  █████╗  ██████╗██╗  ██╗███████╗███╗   ██╗██████╗
    ████╗  ██║██╔══██╗██║    ██╔══██╗██╔══██╗██╔════╝██║ ██╔╝██╔════╝████╗  ██║██╔══██╗
    ██╔██╗ ██║███████║██║    ██████╔╝███████║██║     █████╔╝ █████╗  ██╔██╗ ██║██║  ██║
    ██║╚██╗██║██╔══██║██║    ██╔══██╗██╔══██║██║     ██╔═██╗ ██╔══╝  ██║╚██╗██║██║  ██║
    ██║ ╚████║██║  ██║██║    ██████╔╝██║  ██║╚██████╗██║  ██╗███████╗██║ ╚████║██████╔╝
    ╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝    ╚═════╝ ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝╚═════╝
[/bold cyan]
    [dim]Version {version} | Environment: {environment}[/dim]
    [dim]Multi-tenant AI Backend with Enterprise Features[/dim]
    """


def print_startup_banner(version: str, environment: str) -> None:
    """Print the startup banner to console."""
    from rich.panel import Panel

    banner = create_startup_banner().format(version=version, environment=environment)

    console.print(
        Panel(
            banner,
            border_style="cyan",
            padding=(1, 2),
        )
    )
