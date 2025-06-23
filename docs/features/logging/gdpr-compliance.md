# GDPR Compliance Guide for Logging

## Overview

The nAI Backend v5 logging system is designed with GDPR (General Data Protection Regulation) / DSGVO (Datenschutz-Grundverordnung) compliance at its core. This guide details how our logging system helps you meet GDPR requirements.

## GDPR Principles Implementation

### 1. Lawfulness, Fairness, and Transparency

Our logging system ensures transparency through:

- **Clear documentation** of what is logged
- **Audit trails** for all data processing activities
- **Configurable log levels** to control data collection

```python
# All logging is transparent and auditable
logger.info(
    "User data accessed",
    user_id=current_user.id,
    accessed_user_id=target_user.id,
    purpose="Support request investigation",
    legal_basis="Legitimate interest"
)
```

### 2. Purpose Limitation

Logs are categorized by purpose:

```python
from src.core.logging.audit import AuditEventType

# Security logging
log_audit_event(
    event_type=AuditEventType.LOGIN_ATTEMPT,
    purpose="security_monitoring"
)

# Performance logging
logger.info("Request processed", purpose="performance_analysis")

# Debugging (limited retention)
logger.debug("Detailed trace", purpose="debugging")
```

### 3. Data Minimization

Automatic PII redaction ensures minimal personal data in logs:

```python
# Original data
user_data = {
    "email": "john.doe@example.com",
    "ip": "192.168.1.100",
    "action": "login"
}

# Logged data (automatically redacted)
{
    "email": "[EMAIL]:a3b4c5d6",
    "ip": "[IPv4]:e7f8a9b0",
    "action": "login",
    "_pii_redacted": {"email": 1, "ipv4": 1}
}
```

### 4. Accuracy

- **Immutable logs** with cryptographic signing (when enabled)
- **Timestamp precision** to milliseconds
- **Structured format** preventing data corruption

### 5. Storage Limitation

Automatic retention management:

```python
# Configuration
LOG_RETENTION_DAYS=90  # Default GDPR-compliant retention

# Automatic cleanup
from src.core.logging.retention import LogRetentionManager

manager = LogRetentionManager(
    log_directory="/var/log/app",
    retention_days=90
)

# Scheduled cleanup
await manager.schedule_cleanup(check_interval_hours=24)
```

### 6. Integrity and Confidentiality

- **Encryption at rest** (file system level)
- **Tamper detection** via log signing
- **Access control** through file permissions

### 7. Accountability

Complete audit trail for compliance:

```python
# Log all GDPR-related operations
log_audit_event(
    event_type=AuditEventType.CONSENT_GIVEN,
    user_id=user.id,
    consent_type="marketing_emails",
    consent_version="2.1",
    ip_address=request.client.host
)
```

## GDPR Rights Implementation

### Right to Access (Article 15)

Export all logs related to a specific user:

```python
from src.core.logging.gdpr import GDPRLogManager

manager = GDPRLogManager(log_directory="/var/log/app")

# Export user data
export_path = await manager.export_user_data(
    user_id="12345",
    output_dir="/secure/exports"
)

# Returns JSON with all user's log entries
{
    "export_metadata": {
        "user_id": "12345",
        "export_date": "2024-01-20T10:30:45Z",
        "gdpr_article": "Article 15 - Right of access",
        "export_id": "exp_789abc",
        "total_entries": 1543,
        "date_range": {
            "from": "2023-10-20T00:00:00Z",
            "to": "2024-01-20T10:30:45Z"
        }
    },
    "log_entries": [
        {
            "timestamp": "2024-01-15T14:23:45Z",
            "event": "User login",
            "user_id": "12345",
            "ip_address": "[IPv4]:a1b2c3d4",
            "_original_file": "backend_20240115.log"
        }
        // ... more entries
    ]
}
```

### Right to Rectification (Article 16)

While logs are immutable, corrections are handled through:

```python
# Log correction as a new event
log_audit_event(
    event_type=AuditEventType.DATA_CORRECTION,
    user_id=admin_user.id,
    target_user_id=user.id,
    correction_details={
        "field": "email",
        "old_value_hash": "a1b2c3",
        "reason": "User reported incorrect email"
    },
    reference_log_id="log_123456"
)
```

### Right to Erasure (Article 17)

Complete removal of user data from logs:

```python
# Erase user data
result = await manager.erase_user_data(
    user_id="12345",
    requester_id="admin_001",
    reason="User requested deletion under Article 17"
)

# Result
{
    "user_id": "12345",
    "files_processed": 45,
    "entries_removed": 1543,
    "backup_location": "/secure/gdpr-backups/erasure_20240120_123456.tar.gz",
    "erasure_certificate": {
        "id": "cert_abc123",
        "timestamp": "2024-01-20T10:35:00Z",
        "verified_by": "admin_001"
    }
}
```

### Right to Data Portability (Article 20)

Export data in machine-readable format:

```python
# Export in standard formats
export_formats = ["json", "csv", "xml"]

for format in export_formats:
    await manager.export_user_data(
        user_id="12345",
        output_format=format,
        include_metadata=True
    )
```

### Right to Object (Article 21)

Control logging through consent management:

```python
# Check consent before detailed logging
if user.has_consent("detailed_logging"):
    logger.info("Detailed user action", user_id=user.id, details=action_details)
else:
    logger.info("User action", user_id=user.id)  # Minimal logging
```

## PII Detection and Redaction

### Built-in PII Patterns

The system automatically detects and redacts:

| PII Type | Pattern Example | Redacted Output |
|----------|----------------|-----------------|
| Email | john@example.com | [EMAIL]:a1b2c3 |
| IPv4 | 192.168.1.1 | [IPv4]:d4e5f6 |
| IPv6 | 2001:db8::1 | [IPv6]:g7h8i9 |
| Phone | +1-555-123-4567 | [PHONE]:j1k2l3 |
| SSN | 123-45-6789 | [SSN] |
| Credit Card | 1234-5678-9012-3456 | [CREDIT_CARD] |
| API Key | sk_live_abc123... | [API_KEY] |
| JWT | eyJhbGc... | [JWT] |

### Custom PII Patterns

Add organization-specific PII patterns:

```python
from src.core.logging.filters import PIIRedactionFilter, RedactionRule
import re

# Add custom patterns
filter = PIIRedactionFilter()

# Employee IDs
filter.add_rule(RedactionRule(
    name="employee_id",
    pattern=re.compile(r"EMP\d{6}"),
    replacement="[EMPLOYEE_ID]",
    hash_value=True
))

# Customer numbers
filter.add_rule(RedactionRule(
    name="customer_number",
    pattern=re.compile(r"CUST-\d{8}"),
    replacement="[CUSTOMER]",
    hash_value=True
))

# License plates (German)
filter.add_rule(RedactionRule(
    name="license_plate",
    pattern=re.compile(r"[A-Z]{1,3}-[A-Z]{1,2}\s?\d{1,4}"),
    replacement="[LICENSE_PLATE]",
    hash_value=False  # Don't hash for complete anonymity
))
```

### Pseudonymization

Enable hashing for correlation without exposing PII:

```python
# Configuration
pii_filter = PIIRedactionFilter(
    hash_algorithm="sha256",
    hash_salt=SECRET_SALT  # Tenant-specific salt
)

# Input
logger.info("User action", email="john@example.com")

# Output (same email always produces same hash)
{
    "event": "User action",
    "email": "[EMAIL]:a3b4c5d6",  # Consistent hash
    "_pii_hash_algorithm": "sha256"
}
```

## Consent Management

### Implementing Consent-Based Logging

```python
from enum import Enum
from typing import Dict, Optional

class LoggingConsent(Enum):
    ESSENTIAL = "essential"          # Security, legal requirements
    PERFORMANCE = "performance"      # Performance monitoring
    ANALYTICS = "analytics"         # Usage analytics
    DEBUGGING = "debugging"         # Detailed debugging

class ConsentAwareLogger:
    def __init__(self, base_logger, user_consent: Dict[LoggingConsent, bool]):
        self.logger = base_logger
        self.consent = user_consent
    
    def log(self, level: str, message: str, **kwargs):
        # Always log essential information
        essential_fields = {
            k: v for k, v in kwargs.items() 
            if k in ["user_id", "timestamp", "event_type"]
        }
        
        # Add additional fields based on consent
        if self.consent.get(LoggingConsent.PERFORMANCE):
            essential_fields.update({
                k: v for k, v in kwargs.items()
                if k in ["duration_ms", "response_size"]
            })
        
        if self.consent.get(LoggingConsent.ANALYTICS):
            essential_fields.update({
                k: v for k, v in kwargs.items()
                if k in ["user_agent", "referrer", "session_id"]
            })
        
        getattr(self.logger, level)(message, **essential_fields)
```

### Consent Change Tracking

```python
# Log consent changes
log_audit_event(
    event_type=AuditEventType.CONSENT_UPDATED,
    user_id=user.id,
    changes={
        "analytics": {"old": True, "new": False},
        "debugging": {"old": False, "new": True}
    },
    ip_address=request.client.host,
    timestamp=datetime.utcnow()
)
```

## Retention Policies

### Configuring Retention by Purpose

```python
# Different retention for different log types
RETENTION_POLICIES = {
    "security_logs": 365,      # 1 year for security
    "access_logs": 90,         # 90 days for access logs
    "performance_logs": 30,    # 30 days for performance
    "debug_logs": 7,          # 7 days for debugging
    "audit_logs": 2555        # 7 years for audit (legal requirement)
}

# Apply retention
for log_type, days in RETENTION_POLICIES.items():
    manager = LogRetentionManager(
        log_directory=f"/var/log/app/{log_type}",
        retention_days=days
    )
    await manager.cleanup_old_logs()
```

### Legal Hold Implementation

```python
class LegalHoldManager:
    def __init__(self, log_directory: str):
        self.log_directory = log_directory
        self.holds_file = f"{log_directory}/.legal_holds.json"
    
    async def add_legal_hold(
        self,
        user_id: str,
        case_id: str,
        expires_at: Optional[datetime] = None
    ):
        """Prevent deletion of user's logs during legal proceedings."""
        holds = self._load_holds()
        holds[user_id] = {
            "case_id": case_id,
            "created_at": datetime.utcnow().isoformat(),
            "expires_at": expires_at.isoformat() if expires_at else None
        }
        self._save_holds(holds)
        
        log_audit_event(
            event_type=AuditEventType.LEGAL_HOLD_ADDED,
            user_id=user_id,
            case_id=case_id,
            severity=AuditSeverity.HIGH
        )
```

## Audit Reports

### Generating Compliance Reports

```python
from datetime import datetime, timedelta
from typing import Dict, List

class GDPRComplianceReporter:
    def __init__(self, log_directory: str):
        self.log_directory = log_directory
    
    async def generate_compliance_report(
        self,
        start_date: datetime,
        end_date: datetime
    ) -> Dict:
        """Generate GDPR compliance report for audit."""
        
        report = {
            "period": {
                "start": start_date.isoformat(),
                "end": end_date.isoformat()
            },
            "statistics": {
                "total_logs": 0,
                "pii_redacted": 0,
                "gdpr_requests": {
                    "access": 0,
                    "erasure": 0,
                    "portability": 0,
                    "objection": 0
                },
                "consent_changes": 0,
                "data_breaches": 0
            },
            "retention_compliance": {},
            "security_events": []
        }
        
        # Analyze logs for the period
        # ... implementation ...
        
        return report

# Generate monthly report
reporter = GDPRComplianceReporter("/var/log/app")
report = await reporter.generate_compliance_report(
    start_date=datetime.now() - timedelta(days=30),
    end_date=datetime.now()
)
```

### Data Processing Records

```python
# Record all data processing activities
@dataclass
class DataProcessingActivity:
    id: str
    timestamp: datetime
    processor: str  # Who processed
    purpose: str    # Why processed
    legal_basis: str
    data_categories: List[str]
    recipients: List[str]
    retention_period: int
    
    def log(self):
        log_audit_event(
            event_type=AuditEventType.DATA_PROCESSING,
            activity_id=self.id,
            processor=self.processor,
            purpose=self.purpose,
            legal_basis=self.legal_basis,
            data_categories=self.data_categories,
            recipients=self.recipients,
            retention_days=self.retention_period,
            severity=AuditSeverity.HIGH
        )
```

## Security Measures

### Log Encryption

```python
# Enable encryption for sensitive logs
from cryptography.fernet import Fernet

class EncryptedLogHandler(RotatingFileHandler):
    def __init__(self, filename: str, key: bytes, **kwargs):
        super().__init__(filename, **kwargs)
        self.cipher = Fernet(key)
    
    def emit(self, record):
        msg = self.format(record)
        encrypted = self.cipher.encrypt(msg.encode())
        # Write encrypted data
        with open(self.filename, 'ab') as f:
            f.write(encrypted + b'\n')
```

### Access Control

```python
# Implement role-based access to logs
class LogAccessControl:
    ROLES = {
        "admin": ["read", "write", "delete", "export"],
        "auditor": ["read", "export"],
        "support": ["read"],
        "user": []  # No direct log access
    }
    
    def check_permission(self, user_role: str, action: str) -> bool:
        return action in self.ROLES.get(user_role, [])
    
    def audit_access(self, user_id: str, action: str, resource: str):
        log_audit_event(
            event_type=AuditEventType.LOG_ACCESS,
            user_id=user_id,
            action=action,
            resource=resource,
            severity=AuditSeverity.MEDIUM
        )
```

## Compliance Checklist

### Technical Measures

- [x] Automatic PII redaction
- [x] Configurable retention periods
- [x] Right to erasure implementation
- [x] Right to access/portability
- [x] Audit logging
- [x] Consent tracking
- [x] Pseudonymization support
- [ ] Encryption at rest (OS-level)
- [ ] Log signing/tamper detection

### Organizational Measures

- [ ] Document data processing activities
- [ ] Train staff on GDPR logging requirements
- [ ] Regular compliance audits
- [ ] Incident response procedures
- [ ] Data Protection Officer notification
- [ ] Privacy by Design documentation

### Regular Reviews

1. **Monthly**: Review PII detection patterns
2. **Quarterly**: Audit retention compliance
3. **Annually**: Full GDPR compliance audit
4. **On-demand**: Response to data subject requests

## References

- [GDPR Official Text](https://gdpr-info.eu/)
- [Article 5 - Principles](https://gdpr-info.eu/art-5-gdpr/)
- [Article 15 - Right of access](https://gdpr-info.eu/art-15-gdpr/)
- [Article 17 - Right to erasure](https://gdpr-info.eu/art-17-gdpr/)
- [Article 20 - Right to data portability](https://gdpr-info.eu/art-20-gdpr/)

---

**Guide Version**: 1.0  
**Last Updated**: 2024-01-20  
**Compliance Officer**: privacy@example.com