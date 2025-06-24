"""Schemas for authentication and device registration."""
from datetime import datetime
from typing import Dict, List, Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, validator


class DeviceRegistrationOptions(BaseModel):
    """Options for initiating device registration."""
    
    challenge: str = Field(description="Base64 encoded challenge for registration")
    rp_id: str = Field(description="Relying party identifier (domain)")
    rp_name: str = Field(description="Relying party display name")
    user_id: str = Field(description="Base64 encoded user ID")
    user_name: str = Field(description="Username for the credential")
    user_display_name: str = Field(description="Display name for the credential")
    attestation: str = Field(default="direct", description="Attestation conveyance preference")
    authenticator_selection: Dict = Field(description="Authenticator selection criteria")
    timeout: int = Field(default=60000, description="Timeout in milliseconds")
    exclude_credentials: List[Dict] = Field(
        default_factory=list,
        description="List of credentials to exclude (already registered)"
    )
    pubkey_cred_params: List[Dict] = Field(
        default_factory=lambda: [
            {"type": "public-key", "alg": -7},   # ES256
            {"type": "public-key", "alg": -257}, # RS256
        ],
        description="Supported public key algorithms"
    )

    model_config = ConfigDict(json_schema_extra={
        "example": {
            "challenge": "Y2hhbGxlbmdlLXN0cmluZw==",
            "rp_id": "app.company.com",
            "rp_name": "nAI Platform",
            "user_id": "dXNlci1pZC1zdHJpbmc=",
            "user_name": "user@example.com",
            "user_display_name": "John Doe",
            "authenticator_selection": {
                "user_verification": "required",
                "authenticator_attachment": "platform"
            }
        }
    })


class AuthenticatorResponse(BaseModel):
    """Base authenticator response data."""
    
    client_data_json: str = Field(description="Base64 encoded client data JSON")
    
    @validator("client_data_json")
    def validate_client_data(cls, v):
        """Ensure client data is not empty."""
        if not v:
            raise ValueError("Client data JSON cannot be empty")
        return v


class RegistrationResponse(AuthenticatorResponse):
    """Registration response from authenticator."""
    
    attestation_object: str = Field(description="Base64 encoded attestation object")
    authenticator_data: Optional[str] = Field(None, description="Base64 encoded authenticator data")
    public_key: Optional[str] = Field(None, description="Base64 encoded public key (for some flows)")
    public_key_algorithm: Optional[int] = Field(None, description="Public key algorithm used")
    transports: Optional[List[str]] = Field(None, description="Supported transports")


class DeviceRegistrationVerification(BaseModel):
    """Device registration verification request."""
    
    id: str = Field(description="Base64 encoded credential ID")
    raw_id: str = Field(description="Base64 encoded raw credential ID")
    response: RegistrationResponse = Field(description="Registration response data")
    type: str = Field(default="public-key", description="Credential type")
    authenticator_attachment: Optional[str] = Field(None, description="Authenticator attachment type")
    client_extension_results: Optional[Dict] = Field(default_factory=dict, description="Client extension results")

    model_config = ConfigDict(json_schema_extra={
        "example": {
            "id": "Y3JlZGVudGlhbC1pZA==",
            "raw_id": "Y3JlZGVudGlhbC1pZA==",
            "response": {
                "client_data_json": "Y2xpZW50LWRhdGE=",
                "attestation_object": "YXR0ZXN0YXRpb24tb2JqZWN0"
            },
            "type": "public-key"
        }
    })


class AuthenticationOptions(BaseModel):
    """Options for initiating authentication."""
    
    challenge: str = Field(description="Base64 encoded challenge for authentication")
    timeout: int = Field(default=60000, description="Timeout in milliseconds")
    rp_id: str = Field(description="Relying party identifier")
    user_verification: str = Field(default="required", description="User verification requirement")
    allow_credentials: List[Dict] = Field(
        default_factory=list,
        description="List of allowed credentials for authentication"
    )

    model_config = ConfigDict(json_schema_extra={
        "example": {
            "challenge": "YXV0aC1jaGFsbGVuZ2U=",
            "rp_id": "app.company.com",
            "allow_credentials": [{
                "type": "public-key",
                "id": "Y3JlZGVudGlhbC1pZA=="
            }]
        }
    })


class AuthenticationResponse(AuthenticatorResponse):
    """Authentication response from authenticator."""
    
    authenticator_data: str = Field(description="Base64 encoded authenticator data")
    signature: str = Field(description="Base64 encoded signature")
    user_handle: Optional[str] = Field(None, description="Base64 encoded user handle")


class DeviceAuthenticationVerification(BaseModel):
    """Device authentication verification request."""
    
    id: str = Field(description="Base64 encoded credential ID")
    raw_id: str = Field(description="Base64 encoded raw credential ID")
    response: AuthenticationResponse = Field(description="Authentication response data")
    type: str = Field(default="public-key", description="Credential type")
    client_extension_results: Optional[Dict] = Field(default_factory=dict, description="Client extension results")

    model_config = ConfigDict(json_schema_extra={
        "example": {
            "id": "Y3JlZGVudGlhbC1pZA==",
            "raw_id": "Y3JlZGVudGlhbC1pZA==",
            "response": {
                "client_data_json": "Y2xpZW50LWRhdGE=",
                "authenticator_data": "YXV0aGVudGljYXRvci1kYXRh",
                "signature": "c2lnbmF0dXJl"
            },
            "type": "public-key"
        }
    })


class DeviceInfo(BaseModel):
    """Device information for user device management."""
    
    id: UUID = Field(description="Device unique identifier")
    name: str = Field(description="User-friendly device name")
    type: str = Field(description="Device type (webauthn, passkey, device_cert)")
    trust_level: int = Field(ge=0, le=100, description="Device trust score")
    last_used: datetime = Field(description="Last authentication timestamp")
    created_at: datetime = Field(description="Device registration timestamp")
    is_current: bool = Field(description="Whether this is the currently used device")
    platform: Optional[str] = Field(None, description="Platform information")
    browser: Optional[str] = Field(None, description="Browser information")
    aaguid: Optional[UUID] = Field(None, description="Authenticator AAGUID")
    attestation_type: Optional[str] = Field(None, description="Attestation type used")

    model_config = ConfigDict(
        from_attributes=True,
        json_schema_extra={
            "example": {
                "id": "123e4567-e89b-12d3-a456-426614174000",
                "name": "MacBook Pro - Chrome",
                "type": "webauthn",
                "trust_level": 90,
                "last_used": "2024-01-20T12:00:00Z",
                "created_at": "2024-01-15T10:00:00Z",
                "is_current": True,
                "platform": "macOS",
                "browser": "Chrome 120"
            }
        }
    )


class DeviceListResponse(BaseModel):
    """Response for device list endpoint."""
    
    devices: List[DeviceInfo] = Field(description="List of user devices")
    total: int = Field(description="Total number of devices")
    
    model_config = ConfigDict(json_schema_extra={
        "example": {
            "devices": [{
                "id": "123e4567-e89b-12d3-a456-426614174000",
                "name": "MacBook Pro - Chrome",
                "type": "webauthn",
                "trust_level": 90,
                "last_used": "2024-01-20T12:00:00Z",
                "created_at": "2024-01-15T10:00:00Z",
                "is_current": True
            }],
            "total": 1
        }
    })


class DeviceUpdateRequest(BaseModel):
    """Request to update device information."""
    
    name: Optional[str] = Field(None, min_length=1, max_length=100, description="New device name")
    
    model_config = ConfigDict(json_schema_extra={
        "example": {
            "name": "Personal MacBook Pro"
        }
    })


class DeviceRegistrationSuccess(BaseModel):
    """Successful device registration response."""
    
    device_id: UUID = Field(description="Newly registered device ID")
    device_name: str = Field(description="Device name")
    trust_level: int = Field(description="Initial trust score")
    message: str = Field(default="Device registered successfully")
    
    model_config = ConfigDict(json_schema_extra={
        "example": {
            "device_id": "123e4567-e89b-12d3-a456-426614174000",
            "device_name": "Chrome on macOS",
            "trust_level": 70,
            "message": "Device registered successfully"
        }
    })


class DeviceAuthenticationSuccess(BaseModel):
    """Successful device authentication response."""
    
    access_token: str = Field(description="JWT access token")
    token_type: str = Field(default="bearer", description="Token type")
    expires_in: int = Field(description="Token expiration in seconds")
    refresh_token: Optional[str] = Field(None, description="Refresh token if enabled")
    device_id: UUID = Field(description="Authenticated device ID")
    
    model_config = ConfigDict(json_schema_extra={
        "example": {
            "access_token": "eyJhbGciOiJIUzI1NiIs...",
            "token_type": "bearer",
            "expires_in": 3600,
            "device_id": "123e4567-e89b-12d3-a456-426614174000"
        }
    })