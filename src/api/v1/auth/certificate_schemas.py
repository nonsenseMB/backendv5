"""Pydantic schemas for device certificate API."""
from datetime import datetime
from typing import List, Optional
from uuid import UUID

from pydantic import BaseModel, Field, validator


class CertificateEnrollmentRequest(BaseModel):
    """Request schema for certificate enrollment."""
    
    device_id: UUID = Field(description="Device ID for certificate enrollment")
    certificate: str = Field(description="PEM encoded X.509 certificate")
    certificate_chain: Optional[str] = Field(
        None, 
        description="PEM encoded certificate chain (optional)"
    )
    enrollment_token: Optional[str] = Field(
        None,
        description="Optional enrollment token for auto-approval"
    )
    
    @validator('certificate')
    def validate_certificate_format(cls, v):
        """Validate certificate is in PEM format."""
        if not v.strip().startswith('-----BEGIN CERTIFICATE-----'):
            raise ValueError('Certificate must be in PEM format')
        if not v.strip().endswith('-----END CERTIFICATE-----'):
            raise ValueError('Certificate must be in PEM format')
        return v.strip()
    
    @validator('certificate_chain')
    def validate_chain_format(cls, v):
        """Validate certificate chain format."""
        if v is not None:
            if not v.strip():
                return None
            # Should contain at least one certificate
            if '-----BEGIN CERTIFICATE-----' not in v:
                raise ValueError('Certificate chain must contain PEM certificates')
        return v


class CertificateEnrollmentResponse(BaseModel):
    """Response schema for certificate enrollment."""
    
    certificate_id: UUID = Field(description="Unique certificate ID")
    serial_number: str = Field(description="Certificate serial number")
    fingerprint_sha256: str = Field(description="Certificate SHA256 fingerprint")
    common_name: str = Field(description="Certificate common name")
    issuer_dn: str = Field(description="Certificate issuer DN")
    not_before: datetime = Field(description="Certificate validity start")
    not_after: datetime = Field(description="Certificate validity end")
    is_trusted: bool = Field(description="Whether certificate is trusted")
    trust_score: int = Field(description="Calculated trust score (0-100)")
    status: str = Field(description="Enrollment status")
    message: str = Field(description="Enrollment message")


class CertificateInfo(BaseModel):
    """Certificate information schema."""
    
    id: UUID = Field(description="Certificate ID")
    device_id: UUID = Field(description="Associated device ID")
    serial_number: str = Field(description="Certificate serial number")
    fingerprint_sha256: str = Field(description="SHA256 fingerprint")
    common_name: str = Field(description="Certificate common name")
    issuer_dn: str = Field(description="Issuer distinguished name")
    subject_dn: str = Field(description="Subject distinguished name")
    not_before: datetime = Field(description="Validity start date")
    not_after: datetime = Field(description="Validity end date")
    key_algorithm: Optional[str] = Field(None, description="Key algorithm")
    key_size: Optional[int] = Field(None, description="Key size in bits")
    san_dns_names: List[str] = Field(default=[], description="Subject Alternative Name DNS entries")
    san_ip_addresses: List[str] = Field(default=[], description="Subject Alternative Name IP entries")
    key_usage: List[str] = Field(default=[], description="Key usage extensions")
    extended_key_usage: List[str] = Field(default=[], description="Extended key usage extensions")
    is_active: bool = Field(description="Whether certificate is active")
    is_trusted: bool = Field(description="Whether certificate is trusted")
    revoked: bool = Field(description="Whether certificate is revoked")
    revoked_at: Optional[datetime] = Field(None, description="Revocation timestamp")
    revocation_reason: Optional[str] = Field(None, description="Revocation reason")
    ocsp_url: Optional[str] = Field(None, description="OCSP responder URL")
    crl_distribution_points: List[str] = Field(default=[], description="CRL distribution points")
    last_ocsp_check: Optional[datetime] = Field(None, description="Last OCSP check")
    last_crl_check: Optional[datetime] = Field(None, description="Last CRL check")
    trust_chain_verified: bool = Field(description="Whether trust chain is verified")
    compliance_checked: bool = Field(description="Whether compliance is checked")
    compliance_notes: Optional[str] = Field(None, description="Compliance notes")
    created_at: datetime = Field(description="Certificate creation timestamp")
    updated_at: datetime = Field(description="Certificate update timestamp")


class CertificateListResponse(BaseModel):
    """Response schema for certificate list."""
    
    certificates: List[CertificateInfo] = Field(description="List of certificates")
    total: int = Field(description="Total number of certificates")
    active_count: int = Field(description="Number of active certificates")
    expired_count: int = Field(description="Number of expired certificates")
    revoked_count: int = Field(description="Number of revoked certificates")


class CertificateRevocationRequest(BaseModel):
    """Request schema for certificate revocation."""
    
    reason: str = Field(
        default="unspecified",
        description="Revocation reason",
        pattern="^(unspecified|key_compromise|ca_compromise|affiliation_changed|superseded|cessation_of_operation|certificate_hold|remove_from_crl|privilege_withdrawn|aa_compromise)$"
    )


class CertificateApprovalRequest(BaseModel):
    """Request schema for certificate approval."""
    
    compliance_notes: Optional[str] = Field(
        None,
        description="Compliance verification notes",
        max_length=1000
    )


class CertificateValidationRequest(BaseModel):
    """Request schema for certificate validation."""
    
    certificate: str = Field(description="PEM encoded certificate to validate")
    check_revocation: bool = Field(
        default=True,
        description="Whether to check revocation status"
    )
    required_cn: Optional[str] = Field(
        None,
        description="Required common name (optional)"
    )
    
    @validator('certificate')
    def validate_certificate_format(cls, v):
        """Validate certificate is in PEM format."""
        if not v.strip().startswith('-----BEGIN CERTIFICATE-----'):
            raise ValueError('Certificate must be in PEM format')
        return v.strip()


class CertificateValidationResponse(BaseModel):
    """Response schema for certificate validation."""
    
    is_valid: bool = Field(description="Whether certificate is valid")
    certificate_info: Optional[dict] = Field(None, description="Certificate information")
    validation_errors: List[str] = Field(default=[], description="Validation errors")
    trust_score: Optional[int] = Field(None, description="Calculated trust score")


class EnrollmentTokenRequest(BaseModel):
    """Request schema for enrollment token generation."""
    
    device_id: UUID = Field(description="Device ID for enrollment")
    validity_hours: int = Field(
        default=24,
        description="Token validity in hours",
        ge=1,
        le=168  # Max 1 week
    )


class EnrollmentTokenResponse(BaseModel):
    """Response schema for enrollment token."""
    
    token: str = Field(description="Enrollment token")
    expires_at: datetime = Field(description="Token expiration time")
    device_id: UUID = Field(description="Associated device ID")


class CertificateTrustReport(BaseModel):
    """Certificate trust report schema."""
    
    certificate_id: UUID = Field(description="Certificate ID")
    serial_number: str = Field(description="Certificate serial number")
    trust_score: int = Field(description="Overall trust score")
    trust_factors: dict = Field(description="Trust score breakdown")
    security_assessment: dict = Field(description="Security assessment")
    compliance_status: dict = Field(description="Compliance status")
    recommendations: List[str] = Field(description="Security recommendations")
    last_validated: datetime = Field(description="Last validation timestamp")


class MutualTLSValidationRequest(BaseModel):
    """Request schema for mutual TLS validation."""
    
    client_certificate: str = Field(description="Client certificate from TLS handshake")
    required_cn: Optional[str] = Field(
        None,
        description="Required certificate common name"
    )
    
    @validator('client_certificate')
    def validate_certificate_format(cls, v):
        """Validate certificate format."""
        if not v.strip().startswith('-----BEGIN CERTIFICATE-----'):
            raise ValueError('Certificate must be in PEM format')
        return v.strip()


class MutualTLSValidationResponse(BaseModel):
    """Response schema for mutual TLS validation."""
    
    is_valid: bool = Field(description="Whether mTLS authentication is valid")
    certificate_info: Optional[dict] = Field(None, description="Certificate information")
    device_id: Optional[UUID] = Field(None, description="Authenticated device ID")
    trust_score: Optional[int] = Field(None, description="Device trust score")
    error: Optional[str] = Field(None, description="Validation error if any")