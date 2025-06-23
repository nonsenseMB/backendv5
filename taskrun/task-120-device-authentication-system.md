# Sprint 120: Device Authentication System

## Sprint Goal
Implement WebAuthn/Passkey device authentication system for passwordless login, meeting the strict security requirements of no password fields.

## Duration
Week 4-5 (10 working days)

## Prerequisites
- Sprint 100 & 110 completed
- Authentik configured for WebAuthn
- Frontend capable of WebAuthn API calls

## Tasks

### Task 121: Create Device Registration Endpoints
**Priority**: Critical
**Effort**: 2 days
**Description**: Build API endpoints for device registration flow

**Implementation**:
```python
src/api/v1/auth/
├── __init__.py
├── router.py
├── schemas.py
├── device_endpoints.py
└── validators.py
```

**API Endpoints**:
```
POST /api/v1/auth/device/register/options
     → Generate registration challenge
POST /api/v1/auth/device/register
     → Complete device registration
GET  /api/v1/auth/devices
     → List user's registered devices
DELETE /api/v1/auth/device/{device_id}
     → Remove a device
```

**Registration Schema**:
```python
class DeviceRegistrationOptions(BaseModel):
    challenge: str
    rp_id: str
    rp_name: str
    user_id: str
    user_name: str
    user_display_name: str
    attestation: str = "direct"
    authenticator_selection: dict
    timeout: int = 60000

class DeviceRegistrationVerification(BaseModel):
    credential_id: str
    raw_id: str
    response: dict
    type: str = "public-key"
```

**Success Criteria**:
- [ ] Generate secure challenges
- [ ] Store device credentials
- [ ] Support multiple devices per user
- [ ] Proper error responses

### Task 122: Implement WebAuthn Challenge/Response Flow
**Priority**: Critical
**Effort**: 2 days
**Description**: Core WebAuthn implementation for authentication

**Implementation**:
```python
src/infrastructure/auth/
├── webauthn_manager.py
├── challenge_store.py
└── credential_validator.py
```

**Authentication Flow**:
```
POST /api/v1/auth/device/login/options
     → Generate authentication challenge
POST /api/v1/auth/device/login
     → Verify authentication response
```

**Key Components**:
- Challenge generation (cryptographically secure)
- Challenge storage (Redis with TTL)
- Signature verification
- Counter validation (replay protection)

**WebAuthn Configuration**:
```python
class WebAuthnConfig:
    rp_id: str = "app.company.com"
    rp_name: str = "nAI Platform"
    rp_icon: Optional[str] = None
    user_verification: str = "required"  # MUST be required
    attestation: str = "direct"
    timeout: int = 60000  # 60 seconds
```

**Success Criteria**:
- [ ] Secure challenge generation
- [ ] Proper signature verification
- [ ] Counter increment validation
- [ ] User verification enforced

### Task 123: Build Device Trust Management System
**Priority**: High
**Effort**: 1.5 days
**Description**: Manage device trust levels and attestation

**Implementation**:
```python
src/core/auth/device_trust.py
src/infrastructure/database/models/device.py
```

**Device Model**:
```python
class Device(Base):
    __tablename__ = "user_devices"
    
    id: UUID
    user_id: UUID
    device_name: str
    device_type: str  # webauthn, passkey, device_cert
    credential_id: str  # unique
    public_key: str  # encrypted
    aaguid: Optional[UUID]  # authenticator ID
    sign_count: int
    attestation_format: Optional[str]
    attestation_data: Optional[dict]  # JSON
    trust_level: int  # 0-100
    last_used: datetime
    created_at: datetime
    
    # Indexes for performance
    __table_args__ = (
        Index('idx_device_user', 'user_id'),
        Index('idx_device_credential', 'credential_id', unique=True),
    )
```

**Trust Scoring**:
- Attestation present: +30 points
- TPM/Secure Enclave: +40 points
- Platform authenticator: +20 points
- Regular usage: +10 points

**Success Criteria**:
- [ ] Device trust scoring
- [ ] Attestation verification
- [ ] Trust-based policies
- [ ] Device analytics

### Task 124: Add Device Certificate Support (Optional)
**Priority**: Medium
**Effort**: 1.5 days
**Description**: Support X.509 device certificates for enterprise

**Implementation**:
```python
src/infrastructure/auth/device_cert.py
src/infrastructure/auth/cert_validator.py
```

**Features**:
- Certificate enrollment
- Certificate validation
- CRL/OCSP checking
- Mutual TLS support

**Certificate Storage**:
```python
class DeviceCertificate(Base):
    __tablename__ = "device_certificates"
    
    id: UUID
    device_id: UUID
    certificate: bytes  # DER encoded
    serial_number: str
    issuer_dn: str
    subject_dn: str
    not_before: datetime
    not_after: datetime
    revoked: bool = False
```

**Success Criteria**:
- [ ] Certificate enrollment API
- [ ] Certificate validation
- [ ] Revocation checking
- [ ] Integration with device auth

### Task 125: Create Device Management API
**Priority**: High
**Effort**: 1 day
**Description**: User-facing device management features

**API Endpoints**:
```
GET    /api/v1/auth/devices
       → List all user devices with details
PUT    /api/v1/auth/device/{device_id}
       → Update device name/settings
DELETE /api/v1/auth/device/{device_id}
       → Remove device (with MFA check)
POST   /api/v1/auth/device/{device_id}/verify
       → Re-verify device trust
```

**Device List Response**:
```python
class DeviceInfo(BaseModel):
    id: UUID
    name: str
    type: str
    trust_level: int
    last_used: datetime
    created_at: datetime
    is_current: bool  # Currently used device
    platform: Optional[str]
    browser: Optional[str]
```

**Security Features**:
- Require re-authentication to remove devices
- Email notification on device changes
- Audit log all device operations
- Rate limit device operations

**Success Criteria**:
- [ ] Complete device CRUD
- [ ] Security notifications
- [ ] Audit logging
- [ ] User-friendly responses

## Testing Requirements

### Unit Tests
- Challenge generation randomness
- Signature verification
- Trust scoring logic
- Certificate validation

### Integration Tests
- Full WebAuthn flow
- Multiple device registration
- Device removal with active sessions
- Certificate enrollment

### Security Tests
- Challenge replay attacks
- Counter manipulation
- Invalid signatures
- Attestation bypasses

### Browser Compatibility Tests
- Chrome/Edge (Windows Hello)
- Safari (Touch ID)
- Firefox
- Mobile browsers

## Performance Considerations
- Challenge caching in Redis
- Efficient credential lookup
- Batch device queries
- Async cryptographic operations

## Dependencies

```toml
# Add to pyproject.toml
webauthn = "^2.0.0"          # WebAuthn implementation
cryptography = "^41.0.0"     # Certificate handling
pyOpenSSL = "^23.0.0"        # Certificate validation
redis = "^5.0.0"             # Challenge storage
```

## Documentation Deliverables
- WebAuthn flow diagrams
- Device registration guide
- Trust scoring documentation
- Certificate enrollment guide
- Browser compatibility matrix

## Risks & Mitigations
1. **Risk**: Browser compatibility issues
   **Mitigation**: Comprehensive browser testing, fallback options

2. **Risk**: Lost device scenarios
   **Mitigation**: Multiple device registration, recovery codes

3. **Risk**: WebAuthn complexity for users
   **Mitigation**: Clear UI/UX, help documentation

4. **Risk**: Attestation validation complexity
   **Mitigation**: Use established libraries, thorough testing

## Definition of Done
- [ ] WebAuthn registration working
- [ ] WebAuthn authentication working
- [ ] Multiple devices supported
- [ ] Trust scoring implemented
- [ ] NO password fields anywhere
- [ ] Browser compatibility verified
- [ ] Security tests passing
- [ ] User documentation complete

## Next Sprint Dependencies
This sprint enables:
- Sprint 130: Permission system (needs authenticated users)
- Sprint 150: WebSocket auth (reuses device trust)
- Future: Biometric authentication