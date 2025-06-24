"""Device model for WebAuthn/Passkey authentication."""
from datetime import datetime

from sqlalchemy import (
    JSON,
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import UUID as PostgresUUID
from sqlalchemy.orm import relationship

from src.infrastructure.database.models.base import Base


class Device(Base):
    """
    User authentication device model.
    
    Stores WebAuthn credentials and device information for passwordless authentication.
    Supports multiple devices per user with trust scoring.
    """

    __tablename__ = "user_devices"

    # Primary key
    id = Column(PostgresUUID(as_uuid=True), primary_key=True, nullable=False)

    # Foreign keys
    user_id = Column(
        PostgresUUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    tenant_id = Column(
        PostgresUUID(as_uuid=True),
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )

    # Device information
    device_name = Column(String(255), nullable=False)
    device_type = Column(String(50), nullable=False)  # webauthn, passkey, device_cert
    platform = Column(String(100), nullable=True)  # Windows, macOS, Android, iOS
    browser = Column(String(100), nullable=True)  # Chrome, Safari, Firefox

    # WebAuthn credentials
    credential_id = Column(String(1024), unique=True, nullable=False, index=True)
    public_key = Column(Text, nullable=False)  # Encrypted public key

    # Authenticator information
    aaguid = Column(PostgresUUID(as_uuid=True), nullable=True)  # Authenticator AAGUID
    sign_count = Column(Integer, default=0, nullable=False)  # Signature counter

    # Attestation data
    attestation_format = Column(String(50), nullable=True)  # none, direct, indirect
    attestation_data = Column(JSON, nullable=True)  # Full attestation object

    # Trust and security
    trust_level = Column(Integer, default=0, nullable=False)  # 0-100 trust score
    is_trusted = Column(Boolean, default=False, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)

    # Usage tracking
    last_used = Column(DateTime, nullable=True)
    use_count = Column(Integer, default=0, nullable=False)

    # Metadata
    user_agent = Column(Text, nullable=True)
    ip_address = Column(String(45), nullable=True)  # Last used IP
    metadata = Column(JSON, default=dict, nullable=False)

    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    # Relationships
    user = relationship("User", back_populates="devices", lazy="joined")
    tenant = relationship("Tenant", lazy="joined")

    # Table arguments
    __table_args__ = (
        Index("idx_device_user", "user_id"),
        Index("idx_device_tenant", "tenant_id"),
        Index("idx_device_credential", "credential_id"),
        Index("idx_device_last_used", "last_used"),
        UniqueConstraint("credential_id", name="uq_device_credential_id"),
    )

    def __repr__(self) -> str:
        """String representation."""
        return f"<Device(id={self.id}, name='{self.device_name}', type='{self.device_type}', user_id={self.user_id})>"

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "id": str(self.id),
            "user_id": str(self.user_id),
            "tenant_id": str(self.tenant_id),
            "device_name": self.device_name,
            "device_type": self.device_type,
            "platform": self.platform,
            "browser": self.browser,
            "trust_level": self.trust_level,
            "is_trusted": self.is_trusted,
            "is_active": self.is_active,
            "last_used": self.last_used.isoformat() if self.last_used else None,
            "use_count": self.use_count,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }

    @property
    def is_high_trust(self) -> bool:
        """Check if device has high trust level."""
        return self.trust_level >= 80

    @property
    def is_platform_authenticator(self) -> bool:
        """Check if device is a platform authenticator."""
        return self.attestation_format in ["packed", "tpm", "android-key", "fido-u2f"]

    def update_last_used(self) -> None:
        """Update last used timestamp and increment counter."""
        self.last_used = datetime.utcnow()
        self.use_count += 1

    def calculate_trust_score(self) -> int:
        """
        Calculate device trust score based on various factors.
        
        Returns:
            Trust score between 0-100
        """
        score = 0

        # Base score for successful registration
        score += 10

        # Attestation type scoring
        if self.attestation_format:
            if self.attestation_format == "direct":
                score += 30
            elif self.attestation_format == "indirect":
                score += 20
            elif self.attestation_format == "none":
                score += 5

        # Platform authenticator bonus
        if self.is_platform_authenticator:
            score += 20

        # AAGUID present (authenticator has identity)
        if self.aaguid:
            score += 10

        # Regular usage bonus
        if self.use_count > 10:
            score += 10
        elif self.use_count > 5:
            score += 5

        # Recent usage bonus
        if self.last_used:
            days_since_use = (datetime.utcnow() - self.last_used).days
            if days_since_use < 7:
                score += 10
            elif days_since_use < 30:
                score += 5

        # Cap at 100
        return min(score, 100)
