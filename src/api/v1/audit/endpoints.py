"""
Audit log API endpoints for querying, management, and compliance reporting.
Provides secure access to audit logs with proper authorization and data protection.
"""

from datetime import datetime, timedelta
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.orm import Session

from ....api.dependencies.database import get_db
from ....api.dependencies.permissions import get_current_user, require_permission
from ....core.logging.auth_audit import AuditSeverity, AuthAuditEvent, AuthAuditService
from ....infrastructure.database.models.audit_log import AuditLogRetentionPolicy
from .schemas import (
    AuditLogQueryRequest,
    AuditLogQueryResponse,
    AuditLogSummaryResponse,
    ComplianceExportRequest,
    RetentionPolicyCreateRequest,
    RetentionPolicyResponse,
    RetentionPolicyUpdateRequest,
    SecurityReportRequest,
    SecurityReportResponse,
)

router = APIRouter(prefix="/audit", tags=["audit"])


@router.post("/query", response_model=AuditLogQueryResponse)
async def query_audit_logs(
    query_request: AuditLogQueryRequest,
    request: Request,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Query audit logs with comprehensive filtering and access control.
    Requires appropriate permissions based on query scope.
    """
    # Validate permissions based on query scope
    user_id = UUID(current_user["sub"])

    # Check if user is requesting their own logs vs system-wide logs
    if query_request.user_filter and query_request.user_filter == user_id:
        # Self-access - minimal permissions required
        pass
    elif query_request.tenant_filter:
        # Tenant-specific logs - require tenant audit access
        await require_permission("audit:read:tenant", current_user, db)
    else:
        # System-wide logs - require global audit access
        await require_permission("audit:read:global", current_user, db)

    # Initialize audit service
    audit_service = AuthAuditService(db)

    # Query audit logs
    try:
        result = await audit_service.query_audit_logs(
            requester_id=user_id,
            start_date=query_request.start_date,
            end_date=query_request.end_date,
            user_filter=query_request.user_filter,
            tenant_filter=query_request.tenant_filter,
            event_types=query_request.event_types,
            event_categories=query_request.event_categories,
            severity_levels=query_request.severity_levels,
            success_filter=query_request.success_filter,
            resource_type=query_request.resource_type,
            limit=min(query_request.limit or 100, 1000),  # Cap at 1000 records
            offset=query_request.offset or 0,
            justification=query_request.justification,
            ip_address=request.client.host
        )

        return AuditLogQueryResponse(**result)

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to query audit logs: {str(e)}"
        )


@router.get("/summary", response_model=AuditLogSummaryResponse)
async def get_audit_summary(
    days: int = Query(default=30, ge=1, le=365, description="Number of days to summarize"),
    tenant_id: UUID | None = Query(default=None, description="Filter by tenant"),
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Get audit log summary statistics for the specified time period.
    """
    # Check permissions
    if tenant_id:
        await require_permission("audit:read:tenant", current_user, db)
    else:
        await require_permission("audit:read:global", current_user, db)

    audit_service = AuthAuditService(db)

    # Calculate summary period
    end_date = datetime.utcnow()
    start_date = end_date - timedelta(days=days)

    try:
        # Query summary data
        summary_result = await audit_service.query_audit_logs(
            requester_id=UUID(current_user["sub"]),
            start_date=start_date,
            end_date=end_date,
            tenant_filter=tenant_id,
            limit=0,  # Get count only
            justification="Summary statistics request"
        )

        # Get event type breakdown
        event_breakdown = {}
        severity_breakdown = {}
        category_breakdown = {}

        # Query for detailed breakdown (limited sample)
        detailed_result = await audit_service.query_audit_logs(
            requester_id=UUID(current_user["sub"]),
            start_date=start_date,
            end_date=end_date,
            tenant_filter=tenant_id,
            limit=5000,  # Sample for breakdown
            justification="Summary statistics breakdown"
        )

        # Calculate breakdowns
        for log in detailed_result["logs"]:
            # Event type breakdown
            event_type = log["event_type"]
            event_breakdown[event_type] = event_breakdown.get(event_type, 0) + 1

            # Severity breakdown
            severity = log["severity"]
            severity_breakdown[severity] = severity_breakdown.get(severity, 0) + 1

            # Category breakdown
            category = log["event_category"]
            category_breakdown[category] = category_breakdown.get(category, 0) + 1

        return AuditLogSummaryResponse(
            period_days=days,
            start_date=start_date,
            end_date=end_date,
            total_events=summary_result["total_count"],
            event_type_breakdown=event_breakdown,
            severity_breakdown=severity_breakdown,
            category_breakdown=category_breakdown,
            has_sensitive_events=summary_result["has_sensitive_data"],
            tenant_filter=tenant_id
        )

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to generate audit summary: {str(e)}"
        )


@router.post("/security-report", response_model=SecurityReportResponse)
async def generate_security_report(
    report_request: SecurityReportRequest,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Generate a security-focused audit report highlighting potential threats and anomalies.
    """
    await require_permission("audit:read:security", current_user, db)

    audit_service = AuthAuditService(db)

    try:
        # Query security-relevant events
        security_events = await audit_service.query_audit_logs(
            requester_id=UUID(current_user["sub"]),
            start_date=report_request.start_date,
            end_date=report_request.end_date,
            event_categories=["security", "auth"],
            severity_levels=["warning", "critical"],
            tenant_filter=report_request.tenant_filter,
            limit=10000,  # Large limit for security analysis
            justification=f"Security report generation: {report_request.report_reason}"
        )

        # Analyze security events
        failed_logins = []
        suspicious_activities = []
        privilege_escalations = []
        critical_events = []

        for log in security_events["logs"]:
            event_type = log["event_type"]
            severity = log["severity"]

            if "login.failed" in event_type or "auth.failed" in event_type:
                failed_logins.append(log)
            elif "suspicious" in event_type or "unusual" in event_type:
                suspicious_activities.append(log)
            elif "privilege" in event_type or "escalation" in event_type:
                privilege_escalations.append(log)
            elif severity == "critical":
                critical_events.append(log)

        # Generate recommendations
        recommendations = []
        if len(failed_logins) > 10:
            recommendations.append("High number of failed login attempts detected. Consider implementing rate limiting.")
        if len(privilege_escalations) > 0:
            recommendations.append("Privilege escalation events detected. Review user permissions and access controls.")
        if len(critical_events) > 5:
            recommendations.append("Multiple critical security events detected. Immediate investigation recommended.")

        return SecurityReportResponse(
            report_id=str(UUID("12345678-1234-5678-9012-123456789012")),  # Generate actual UUID in production
            generated_at=datetime.utcnow(),
            period_start=report_request.start_date,
            period_end=report_request.end_date,
            total_security_events=len(security_events["logs"]),
            failed_login_attempts=len(failed_logins),
            suspicious_activities=len(suspicious_activities),
            privilege_escalations=len(privilege_escalations),
            critical_events=len(critical_events),
            recommendations=recommendations,
            generated_by=UUID(current_user["sub"]),
            tenant_filter=report_request.tenant_filter
        )

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to generate security report: {str(e)}"
        )


@router.post("/export-compliance", response_model=dict[str, str])
async def export_compliance_data(
    export_request: ComplianceExportRequest,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Export audit logs for compliance purposes (GDPR, SOX, etc.).
    Returns a secure download URL for the compliance export.
    """
    await require_permission("audit:export:compliance", current_user, db)

    audit_service = AuthAuditService(db)

    try:
        # Query compliance-relevant logs
        compliance_logs = await audit_service.query_audit_logs(
            requester_id=UUID(current_user["sub"]),
            start_date=export_request.start_date,
            end_date=export_request.end_date,
            user_filter=export_request.user_filter,
            tenant_filter=export_request.tenant_filter,
            limit=100000,  # Large limit for compliance export
            justification=f"Compliance export: {export_request.compliance_framework} - {export_request.export_reason}"
        )

        # Log the export event
        await audit_service.log_auth_event(
            event_type=AuthAuditEvent.DATA_EXPORT,
            user_id=UUID(current_user["sub"]),
            tenant_id=export_request.tenant_filter,
            action="compliance_export",
            details={
                "compliance_framework": export_request.compliance_framework,
                "export_reason": export_request.export_reason,
                "records_exported": compliance_logs["total_count"],
                "user_filter": str(export_request.user_filter) if export_request.user_filter else None
            },
            severity=AuditSeverity.CRITICAL,
            success=True
        )

        # In a real implementation, this would:
        # 1. Generate a secure export file (JSON/CSV)
        # 2. Store it in secure temporary storage
        # 3. Return a time-limited signed URL
        # 4. Schedule automatic cleanup

        export_url = f"https://secure-exports.example.com/compliance/{UUID('12345678-1234-5678-9012-123456789012')}"

        return {
            "export_url": export_url,
            "expires_at": (datetime.utcnow() + timedelta(hours=24)).isoformat(),
            "record_count": compliance_logs["total_count"],
            "export_id": str(UUID("12345678-1234-5678-9012-123456789012"))
        }

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to export compliance data: {str(e)}"
        )


@router.get("/retention-policies", response_model=list[RetentionPolicyResponse])
async def list_retention_policies(
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """List all active audit log retention policies."""
    await require_permission("audit:manage:policies", current_user, db)

    try:
        policies = (
            db.query(AuditLogRetentionPolicy)
            .filter(AuditLogRetentionPolicy.is_active == True)
            .all()
        )

        return [
            RetentionPolicyResponse(
                id=policy.id,
                policy_name=policy.policy_name,
                description=policy.description,
                event_types=policy.event_types,
                event_categories=policy.event_categories,
                severity_levels=policy.severity_levels,
                compliance_tags=policy.compliance_tags,
                retention_days=policy.retention_days,
                is_default=policy.is_default,
                is_active=policy.is_active,
                created_at=policy.created_at,
                created_by=policy.created_by
            )
            for policy in policies
        ]

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to list retention policies: {str(e)}"
        )


@router.post("/retention-policies", response_model=RetentionPolicyResponse)
async def create_retention_policy(
    policy_request: RetentionPolicyCreateRequest,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Create a new audit log retention policy."""
    await require_permission("audit:manage:policies", current_user, db)

    try:
        # Check if policy name already exists
        existing_policy = (
            db.query(AuditLogRetentionPolicy)
            .filter(AuditLogRetentionPolicy.policy_name == policy_request.policy_name)
            .first()
        )

        if existing_policy:
            raise HTTPException(
                status_code=400,
                detail=f"Retention policy '{policy_request.policy_name}' already exists"
            )

        # Create new policy
        new_policy = AuditLogRetentionPolicy(
            policy_name=policy_request.policy_name,
            description=policy_request.description,
            event_types=policy_request.event_types or [],
            event_categories=policy_request.event_categories or [],
            severity_levels=policy_request.severity_levels or [],
            compliance_tags=policy_request.compliance_tags or [],
            retention_days=policy_request.retention_days,
            is_default=policy_request.is_default,
            archive_after_days=policy_request.archive_after_days,
            encrypt_sensitive=policy_request.encrypt_sensitive,
            require_approval_for_access=policy_request.require_approval_for_access,
            created_by=UUID(current_user["sub"])
        )

        db.add(new_policy)
        db.commit()
        db.refresh(new_policy)

        # Log policy creation
        audit_service = AuthAuditService(db)
        await audit_service.log_auth_event(
            event_type=AuthAuditEvent.ADMIN_ACTION,
            user_id=UUID(current_user["sub"]),
            action="create_retention_policy",
            details={
                "policy_name": policy_request.policy_name,
                "retention_days": policy_request.retention_days,
                "is_default": policy_request.is_default
            },
            severity=AuditSeverity.INFO,
            success=True
        )

        return RetentionPolicyResponse(
            id=new_policy.id,
            policy_name=new_policy.policy_name,
            description=new_policy.description,
            event_types=new_policy.event_types,
            event_categories=new_policy.event_categories,
            severity_levels=new_policy.severity_levels,
            compliance_tags=new_policy.compliance_tags,
            retention_days=new_policy.retention_days,
            is_default=new_policy.is_default,
            is_active=new_policy.is_active,
            created_at=new_policy.created_at,
            created_by=new_policy.created_by
        )

    except Exception as e:
        if "already exists" in str(e):
            raise
        raise HTTPException(
            status_code=500,
            detail=f"Failed to create retention policy: {str(e)}"
        )


@router.put("/retention-policies/{policy_id}", response_model=RetentionPolicyResponse)
async def update_retention_policy(
    policy_id: UUID,
    policy_update: RetentionPolicyUpdateRequest,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Update an existing audit log retention policy."""
    await require_permission("audit:manage:policies", current_user, db)

    try:
        # Get existing policy
        policy = (
            db.query(AuditLogRetentionPolicy)
            .filter(AuditLogRetentionPolicy.id == policy_id)
            .first()
        )

        if not policy:
            raise HTTPException(
                status_code=404,
                detail="Retention policy not found"
            )

        # Update policy fields
        update_data = policy_update.dict(exclude_unset=True)
        for field, value in update_data.items():
            setattr(policy, field, value)

        policy.last_modified_by = UUID(current_user["sub"])
        policy.last_modified_at = datetime.utcnow()

        db.commit()
        db.refresh(policy)

        # Log policy update
        audit_service = AuthAuditService(db)
        await audit_service.log_auth_event(
            event_type=AuthAuditEvent.ADMIN_ACTION,
            user_id=UUID(current_user["sub"]),
            action="update_retention_policy",
            details={
                "policy_id": str(policy_id),
                "policy_name": policy.policy_name,
                "updated_fields": list(update_data.keys())
            },
            severity=AuditSeverity.INFO,
            success=True
        )

        return RetentionPolicyResponse(
            id=policy.id,
            policy_name=policy.policy_name,
            description=policy.description,
            event_types=policy.event_types,
            event_categories=policy.event_categories,
            severity_levels=policy.severity_levels,
            compliance_tags=policy.compliance_tags,
            retention_days=policy.retention_days,
            is_default=policy.is_default,
            is_active=policy.is_active,
            created_at=policy.created_at,
            created_by=policy.created_by
        )

    except Exception as e:
        if "not found" in str(e):
            raise
        raise HTTPException(
            status_code=500,
            detail=f"Failed to update retention policy: {str(e)}"
        )


@router.delete("/retention-policies/{policy_id}")
async def delete_retention_policy(
    policy_id: UUID,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Deactivate an audit log retention policy."""
    await require_permission("audit:manage:policies", current_user, db)

    try:
        # Get existing policy
        policy = (
            db.query(AuditLogRetentionPolicy)
            .filter(AuditLogRetentionPolicy.id == policy_id)
            .first()
        )

        if not policy:
            raise HTTPException(
                status_code=404,
                detail="Retention policy not found"
            )

        if policy.is_default:
            raise HTTPException(
                status_code=400,
                detail="Cannot delete the default retention policy"
            )

        # Deactivate instead of deleting for audit trail
        policy.is_active = False
        policy.last_modified_by = UUID(current_user["sub"])
        policy.last_modified_at = datetime.utcnow()

        db.commit()

        # Log policy deletion
        audit_service = AuthAuditService(db)
        await audit_service.log_auth_event(
            event_type=AuthAuditEvent.ADMIN_ACTION,
            user_id=UUID(current_user["sub"]),
            action="delete_retention_policy",
            details={
                "policy_id": str(policy_id),
                "policy_name": policy.policy_name
            },
            severity=AuditSeverity.WARNING,
            success=True
        )

        return {"message": "Retention policy deactivated successfully"}

    except Exception as e:
        if "not found" in str(e) or "Cannot delete" in str(e):
            raise
        raise HTTPException(
            status_code=500,
            detail=f"Failed to delete retention policy: {str(e)}"
        )


@router.post("/cleanup")
async def cleanup_expired_logs(
    batch_size: int = Query(default=1000, ge=100, le=10000, description="Batch size for cleanup"),
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Manually trigger cleanup of expired audit logs.
    Normally runs automatically, but can be triggered manually for maintenance.
    """
    await require_permission("audit:manage:cleanup", current_user, db)

    audit_service = AuthAuditService(db)

    try:
        cleaned_count = await audit_service.cleanup_expired_logs(batch_size=batch_size)

        # Log cleanup event
        await audit_service.log_auth_event(
            event_type=AuthAuditEvent.ADMIN_ACTION,
            user_id=UUID(current_user["sub"]),
            action="manual_log_cleanup",
            details={
                "cleaned_count": cleaned_count,
                "batch_size": batch_size
            },
            severity=AuditSeverity.INFO,
            success=True
        )

        return {
            "message": "Log cleanup completed",
            "cleaned_count": cleaned_count,
            "batch_size": batch_size
        }

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to cleanup expired logs: {str(e)}"
        )
