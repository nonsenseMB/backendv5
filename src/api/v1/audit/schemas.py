"""
Pydantic schemas for audit logging API endpoints.
Defines request/response models for audit log queries and management.
"""

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field, validator


class AuditLogQueryRequest(BaseModel):
    """Request model for querying audit logs."""

    start_date: datetime | None = Field(
        None,
        description="Start date for log query (inclusive)"
    )
    end_date: datetime | None = Field(
        None,
        description="End date for log query (inclusive)"
    )
    user_filter: UUID | None = Field(
        None,
        description="Filter logs for specific user ID"
    )
    tenant_filter: UUID | None = Field(
        None,
        description="Filter logs for specific tenant ID"
    )
    event_types: list[str] | None = Field(
        None,
        description="Filter by specific event types"
    )
    event_categories: list[str] | None = Field(
        None,
        description="Filter by event categories (auth, data, admin, security, system)"
    )
    severity_levels: list[str] | None = Field(
        None,
        description="Filter by severity levels (info, warning, critical)"
    )
    success_filter: bool | None = Field(
        None,
        description="Filter by success/failure status"
    )
    resource_type: str | None = Field(
        None,
        description="Filter by resource type"
    )
    limit: int | None = Field(
        100,
        ge=1,
        le=1000,
        description="Maximum number of records to return"
    )
    offset: int | None = Field(
        0,
        ge=0,
        description="Number of records to skip"
    )
    justification: str | None = Field(
        None,
        description="Justification for accessing audit logs (required for sensitive data)"
    )

    @validator('end_date')
    def end_date_after_start_date(cls, v, values):
        if v and values.get('start_date') and v <= values['start_date']:
            raise ValueError('end_date must be after start_date')
        return v

    @validator('event_categories')
    def validate_event_categories(cls, v):
        if v:
            valid_categories = {'auth', 'data', 'admin', 'security', 'system', 'user', 'tenant'}
            invalid_categories = set(v) - valid_categories
            if invalid_categories:
                raise ValueError(f'Invalid event categories: {invalid_categories}')
        return v

    @validator('severity_levels')
    def validate_severity_levels(cls, v):
        if v:
            valid_severities = {'info', 'warning', 'critical'}
            invalid_severities = set(v) - valid_severities
            if invalid_severities:
                raise ValueError(f'Invalid severity levels: {invalid_severities}')
        return v


class AuditLogEntry(BaseModel):
    """Individual audit log entry in query response."""

    id: str
    timestamp: datetime
    event_type: str
    event_category: str
    severity: str
    user_id: str | None = None
    tenant_id: str | None = None
    resource_type: str | None = None
    resource_id: str | None = None
    action: str | None = None
    success: bool | None = None
    details: dict[str, Any] = Field(default_factory=dict)
    is_sensitive: bool = False

    # Optional fields included for authorized users
    ip_address_hash: str | None = None
    user_agent: str | None = None
    request_id: str | None = None
    error_code: str | None = None
    error_message: str | None = None
    duration_ms: int | None = None
    compliance_tags: list[str] | None = None


class AuditLogQueryResponse(BaseModel):
    """Response model for audit log queries."""

    logs: list[AuditLogEntry]
    total_count: int = Field(description="Total number of matching logs")
    returned_count: int = Field(description="Number of logs returned in this response")
    offset: int = Field(description="Offset used in the query")
    limit: int = Field(description="Limit used in the query")
    has_sensitive_data: bool = Field(description="Whether response contains sensitive data")
    query_duration_ms: int = Field(description="Query execution time in milliseconds")


class AuditLogSummaryResponse(BaseModel):
    """Response model for audit log summary statistics."""

    period_days: int = Field(description="Number of days covered by summary")
    start_date: datetime = Field(description="Start of summary period")
    end_date: datetime = Field(description="End of summary period")
    total_events: int = Field(description="Total number of audit events")
    event_type_breakdown: dict[str, int] = Field(description="Count by event type")
    severity_breakdown: dict[str, int] = Field(description="Count by severity level")
    category_breakdown: dict[str, int] = Field(description="Count by event category")
    has_sensitive_events: bool = Field(description="Whether period contains sensitive events")
    tenant_filter: UUID | None = Field(description="Tenant filter applied to summary")


class SecurityReportRequest(BaseModel):
    """Request model for security-focused audit reports."""

    start_date: datetime = Field(description="Start date for security report")
    end_date: datetime = Field(description="End date for security report")
    tenant_filter: UUID | None = Field(
        None,
        description="Filter report to specific tenant"
    )
    report_reason: str = Field(
        description="Reason for generating security report"
    )

    @validator('end_date')
    def end_date_after_start_date(cls, v, values):
        if v <= values['start_date']:
            raise ValueError('end_date must be after start_date')
        return v


class SecurityReportResponse(BaseModel):
    """Response model for security audit reports."""

    report_id: str = Field(description="Unique identifier for this report")
    generated_at: datetime = Field(description="When the report was generated")
    period_start: datetime = Field(description="Start of report period")
    period_end: datetime = Field(description="End of report period")
    total_security_events: int = Field(description="Total security-related events")
    failed_login_attempts: int = Field(description="Number of failed login attempts")
    suspicious_activities: int = Field(description="Number of suspicious activities")
    privilege_escalations: int = Field(description="Number of privilege escalation events")
    critical_events: int = Field(description="Number of critical security events")
    recommendations: list[str] = Field(description="Security recommendations")
    generated_by: UUID = Field(description="User who generated the report")
    tenant_filter: UUID | None = Field(description="Tenant filter applied to report")


class ComplianceExportRequest(BaseModel):
    """Request model for compliance data export."""

    start_date: datetime = Field(description="Start date for export")
    end_date: datetime = Field(description="End date for export")
    compliance_framework: str = Field(
        description="Compliance framework (GDPR, SOX, HIPAA, etc.)"
    )
    export_reason: str = Field(
        description="Reason for compliance data export"
    )
    user_filter: UUID | None = Field(
        None,
        description="Filter export to specific user"
    )
    tenant_filter: UUID | None = Field(
        None,
        description="Filter export to specific tenant"
    )

    @validator('end_date')
    def end_date_after_start_date(cls, v, values):
        if v <= values['start_date']:
            raise ValueError('end_date must be after start_date')
        return v

    @validator('compliance_framework')
    def validate_compliance_framework(cls, v):
        valid_frameworks = {'GDPR', 'SOX', 'HIPAA', 'PCI-DSS', 'ISO27001', 'NIST'}
        if v.upper() not in valid_frameworks:
            raise ValueError(f'Invalid compliance framework. Must be one of: {valid_frameworks}')
        return v.upper()


class RetentionPolicyCreateRequest(BaseModel):
    """Request model for creating retention policies."""

    policy_name: str = Field(
        description="Unique name for the retention policy",
        min_length=1,
        max_length=100
    )
    description: str | None = Field(
        None,
        description="Description of the retention policy"
    )
    event_types: list[str] | None = Field(
        None,
        description="Event types this policy applies to"
    )
    event_categories: list[str] | None = Field(
        None,
        description="Event categories this policy applies to"
    )
    severity_levels: list[str] | None = Field(
        None,
        description="Severity levels this policy applies to"
    )
    compliance_tags: list[str] | None = Field(
        None,
        description="Compliance frameworks this policy applies to"
    )
    retention_days: int = Field(
        description="Number of days to retain logs",
        ge=1,
        le=3650  # 10 years maximum
    )
    is_default: bool = Field(
        False,
        description="Whether this is the default retention policy"
    )
    archive_after_days: int | None = Field(
        None,
        description="Move to archive storage after N days",
        ge=1
    )
    encrypt_sensitive: bool = Field(
        True,
        description="Whether to encrypt sensitive logs"
    )
    require_approval_for_access: bool = Field(
        False,
        description="Whether access to these logs requires approval"
    )

    @validator('archive_after_days')
    def archive_before_retention(cls, v, values):
        if v and values.get('retention_days') and v >= values['retention_days']:
            raise ValueError('archive_after_days must be less than retention_days')
        return v


class RetentionPolicyUpdateRequest(BaseModel):
    """Request model for updating retention policies."""

    description: str | None = None
    event_types: list[str] | None = None
    event_categories: list[str] | None = None
    severity_levels: list[str] | None = None
    compliance_tags: list[str] | None = None
    retention_days: int | None = Field(None, ge=1, le=3650)
    archive_after_days: int | None = Field(None, ge=1)
    encrypt_sensitive: bool | None = None
    require_approval_for_access: bool | None = None
    is_active: bool | None = None

    @validator('archive_after_days')
    def archive_before_retention(cls, v, values):
        if v and values.get('retention_days') and v >= values['retention_days']:
            raise ValueError('archive_after_days must be less than retention_days')
        return v


class RetentionPolicyResponse(BaseModel):
    """Response model for retention policies."""

    id: UUID = Field(description="Unique identifier for the policy")
    policy_name: str = Field(description="Name of the retention policy")
    description: str | None = Field(description="Description of the policy")
    event_types: list[str] = Field(description="Event types this policy applies to")
    event_categories: list[str] = Field(description="Event categories this policy applies to")
    severity_levels: list[str] = Field(description="Severity levels this policy applies to")
    compliance_tags: list[str] = Field(description="Compliance frameworks this policy applies to")
    retention_days: int = Field(description="Number of days to retain logs")
    is_default: bool = Field(description="Whether this is the default policy")
    is_active: bool = Field(description="Whether this policy is active")
    created_at: datetime = Field(description="When the policy was created")
    created_by: UUID = Field(description="User who created the policy")

    class Config:
        from_attributes = True
