"""
Authentication models - NO PASSWORD FIELDS!
All authentication is handled by Authentik.
"""

from sqlalchemy import JSON, Boolean, Column, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from ..base import BaseModel


class User(BaseModel):
    """
    User model - NO PASSWORD FIELD!
    Authentication is handled entirely by Authentik.
    """
    __tablename__ = 'users'

    # Authentik Integration
    external_id = Column(String(255), unique=True, nullable=False)  # Authentik user ID
    email = Column(String(255), unique=True, nullable=False)
    username = Column(String(255), unique=True, nullable=True)

    # Profile
    full_name = Column(String(255), nullable=True)
    avatar_url = Column(Text, nullable=True)
    language = Column(String(10), default='en')
    timezone = Column(String(50), default='UTC')

    # Status
    is_active = Column(Boolean, default=True)
    is_verified = Column(Boolean, default=False)
    last_seen_at = Column(DateTime, nullable=True)

    # Additional data
    extra_data = Column('metadata', JSON, default=dict)

    # Relationships
    devices = relationship("UserDevice", back_populates="user", cascade="all, delete-orphan")
    tenants = relationship("TenantUser", back_populates="user", foreign_keys="TenantUser.user_id")
    conversations = relationship("Conversation", back_populates="user")
    preferences = relationship("UserPreferences", back_populates="user", uselist=False)
    sessions = relationship("UserSession", back_populates="user", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<User(email='{self.email}', external_id='{self.external_id}')>"


class UserDevice(BaseModel):
    """
    Device-based authentication only.
    Supports WebAuthn, Passkeys, and Device Certificates.
    """
    __tablename__ = 'user_devices'

    # Foreign Key
    user_id = Column(UUID(as_uuid=True), ForeignKey('users.id', ondelete='CASCADE'), nullable=False)

    # Device Info
    device_name = Column(String(255), nullable=False)
    device_type = Column(String(50), nullable=False)  # webauthn, passkey, certificate
    device_id = Column(String(255), unique=True, nullable=False)

    # Authentication
    credential_id = Column(String(255), unique=True, nullable=True)
    public_key = Column(Text, nullable=True)
    attestation_object = Column(JSON, nullable=True)
    sign_count = Column(Integer, default=0)  # For replay protection

    # Trust
    is_trusted = Column(Boolean, default=False)
    trust_score = Column(Float, default=0.0)

    # Usage
    last_used_at = Column(DateTime, nullable=True)
    use_count = Column(Integer, default=0)

    # Status
    is_active = Column(Boolean, default=True)

    # Additional data
    user_agent = Column(Text, nullable=True)
    extra_data = Column('metadata', JSON, default=dict)

    # Relationships
    user = relationship("User", back_populates="devices")
    certificates = relationship("DeviceCertificate", back_populates="device", cascade="all, delete-orphan")


    def __repr__(self):
        return f"<UserDevice(user_id={self.user_id}, device_name='{self.device_name}', type='{self.device_type}')>"


class DeviceCertificate(BaseModel):
    """
    X.509 device certificates for enterprise authentication.
    Enables mutual TLS and certificate-based device authentication.
    """
    __tablename__ = 'device_certificates'

    # Certificate identification
    device_id = Column(UUID(as_uuid=True), ForeignKey('user_devices.id', ondelete='CASCADE'), nullable=False)
    certificate = Column(Text, nullable=False)  # PEM encoded certificate
    certificate_chain = Column(Text, nullable=True)  # PEM encoded chain
    serial_number = Column(String(255), unique=True, nullable=False)
    fingerprint_sha256 = Column(String(64), unique=True, nullable=False)  # Hex encoded

    # Certificate details
    issuer_dn = Column(Text, nullable=False)  # Distinguished Name
    subject_dn = Column(Text, nullable=False)  # Distinguished Name
    common_name = Column(String(255), nullable=False)
    san_dns_names = Column(JSON, default=list)  # Subject Alternative Names
    san_ip_addresses = Column(JSON, default=list)

    # Certificate validity
    not_before = Column(DateTime, nullable=False)
    not_after = Column(DateTime, nullable=False)
    key_usage = Column(JSON, nullable=True)  # List of key usage extensions
    extended_key_usage = Column(JSON, nullable=True)  # List of extended key usage

    # Certificate status
    is_active = Column(Boolean, default=True)
    revoked = Column(Boolean, default=False)
    revoked_at = Column(DateTime, nullable=True)
    revocation_reason = Column(String(255), nullable=True)

    # OCSP/CRL info
    ocsp_url = Column(Text, nullable=True)
    crl_distribution_points = Column(JSON, default=list)
    last_ocsp_check = Column(DateTime, nullable=True)
    last_crl_check = Column(DateTime, nullable=True)

    # Trust and compliance
    is_trusted = Column(Boolean, default=False)
    trust_chain_verified = Column(Boolean, default=False)
    compliance_checked = Column(Boolean, default=False)
    compliance_notes = Column(Text, nullable=True)

    # Relationships
    device = relationship("UserDevice", back_populates="certificates")

    def __repr__(self):
        return f"<DeviceCertificate(serial={self.serial_number}, cn='{self.common_name}', device_id={self.device_id})>"
