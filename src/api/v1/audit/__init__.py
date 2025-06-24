"""
Audit logging API module.
Provides endpoints for querying, managing, and exporting audit logs.
"""

from .endpoints import router as audit_router

__all__ = ["audit_router"]
