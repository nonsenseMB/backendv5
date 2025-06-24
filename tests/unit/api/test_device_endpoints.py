"""Unit tests for device authentication endpoints."""
import base64
import json
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import UUID, uuid4

import pytest
from fastapi import HTTPException, status

from src.api.v1.auth.device_endpoints import (
    complete_device_registration,
    delete_device,
    generate_registration_options,
    list_user_devices,
    update_device,
)
from src.api.v1.auth.schemas import (
    DeviceRegistrationVerification,
    DeviceUpdateRequest,
    RegistrationResponse,
)
from src.infrastructure.auth.webauthn_manager import VerificationResult
from src.infrastructure.database.models.auth import User, UserDevice


@pytest.fixture
def mock_user():
    """Create a mock authenticated user."""
    user = MagicMock(spec=User)
    user.id = uuid4()
    user.tenant_id = uuid4()
    user.email = "test@example.com"
    user.full_name = "Test User"
    user.is_active = True
    return user


@pytest.fixture
def mock_device():
    """Create a mock device."""
    device = MagicMock(spec=UserDevice)
    device.id = uuid4()
    device.user_id = uuid4()
    device.device_name = "Test Device"
    device.device_type = "webauthn"
    device.device_id = "test-device-id"
    device.credential_id = "test-credential-id"
    device.public_key = "test-public-key"
    device.trust_score = 75.0
    device.is_trusted = False
    device.is_active = True
    device.last_used_at = datetime.utcnow()
    device.created_at = datetime.utcnow()
    device.user_agent = "Mozilla/5.0"
    return device


@pytest.fixture
def mock_request():
    """Create a mock request."""
    request = MagicMock()
    request.headers = {"User-Agent": "Mozilla/5.0"}
    request.state = MagicMock()
    return request


@pytest.fixture
def mock_session():
    """Create a mock database session."""
    return AsyncMock()


class TestGenerateRegistrationOptions:
    """Test registration options generation."""
    
    @pytest.mark.asyncio
    async def test_generate_options_success(self, mock_user, mock_request, mock_session):
        """Test successful generation of registration options."""
        # Mock dependencies
        with patch("src.api.v1.auth.device_endpoints.get_redis_client") as mock_redis:
            with patch("src.api.v1.auth.device_endpoints.ChallengeStore") as mock_store:
                with patch("src.api.v1.auth.device_endpoints.WebAuthnManager") as mock_manager:
                    with patch("src.api.v1.auth.device_endpoints.UnitOfWork") as mock_uow:
                        # Setup mocks
                        mock_redis.return_value = AsyncMock()
                        mock_store_instance = AsyncMock()
                        mock_store.return_value = mock_store_instance
                        
                        mock_manager_instance = AsyncMock()
                        mock_manager.return_value = mock_manager_instance
                        mock_manager_instance.generate_registration_options.return_value = MagicMock(
                            challenge="test-challenge",
                            rp_id="example.com",
                            rp_name="Example App"
                        )
                        
                        mock_repo = AsyncMock()
                        mock_repo.get_user_devices.return_value = []
                        
                        mock_uow_instance = AsyncMock()
                        mock_uow.return_value.__aenter__.return_value = mock_uow_instance
                        
                        with patch("src.api.v1.auth.device_endpoints.DeviceRepository") as mock_repo_class:
                            mock_repo_class.return_value = mock_repo
                            
                            # Call function
                            result = await generate_registration_options(
                                request=mock_request,
                                current_user=mock_user,
                                session=mock_session
                            )
                            
                            # Assertions
                            assert result.challenge == "test-challenge"
                            assert result.rp_id == "example.com"
                            mock_store_instance.store_challenge.assert_called_once()
                            mock_repo.get_user_devices.assert_called_once_with(mock_user.id)
    
    @pytest.mark.asyncio
    async def test_generate_options_with_existing_devices(self, mock_user, mock_device, mock_request, mock_session):
        """Test generation with existing devices to exclude."""
        with patch("src.api.v1.auth.device_endpoints.get_redis_client") as mock_redis:
            with patch("src.api.v1.auth.device_endpoints.ChallengeStore") as mock_store:
                with patch("src.api.v1.auth.device_endpoints.WebAuthnManager") as mock_manager:
                    with patch("src.api.v1.auth.device_endpoints.UnitOfWork") as mock_uow:
                        # Setup mocks
                        mock_redis.return_value = AsyncMock()
                        mock_store_instance = AsyncMock()
                        mock_store.return_value = mock_store_instance
                        
                        mock_manager_instance = AsyncMock()
                        mock_manager.return_value = mock_manager_instance
                        mock_manager_instance.generate_registration_options.return_value = MagicMock(
                            challenge="test-challenge",
                            exclude_credentials=[{"type": "public-key", "id": mock_device.credential_id}]
                        )
                        
                        mock_repo = AsyncMock()
                        mock_repo.get_user_devices.return_value = [mock_device]
                        
                        mock_uow_instance = AsyncMock()
                        mock_uow.return_value.__aenter__.return_value = mock_uow_instance
                        
                        with patch("src.api.v1.auth.device_endpoints.DeviceRepository") as mock_repo_class:
                            mock_repo_class.return_value = mock_repo
                            
                            # Call function
                            result = await generate_registration_options(
                                request=mock_request,
                                current_user=mock_user,
                                session=mock_session
                            )
                            
                            # Assertions
                            assert len(result.exclude_credentials) == 1
                            assert result.exclude_credentials[0]["id"] == mock_device.credential_id


class TestCompleteDeviceRegistration:
    """Test device registration completion."""
    
    @pytest.mark.asyncio
    async def test_complete_registration_success(self, mock_user, mock_request, mock_session):
        """Test successful device registration."""
        # Create verification data
        verification = DeviceRegistrationVerification(
            id="new-credential-id",
            raw_id="new-credential-id",
            response=RegistrationResponse(
                client_data_json=base64.b64encode(json.dumps({
                    "type": "webauthn.create",
                    "challenge": "test-challenge",
                    "origin": "https://example.com"
                }).encode()).decode(),
                attestation_object="fake-attestation"
            ),
            type="public-key"
        )
        
        with patch("src.api.v1.auth.device_endpoints.get_redis_client") as mock_redis:
            with patch("src.api.v1.auth.device_endpoints.ChallengeStore") as mock_store:
                with patch("src.api.v1.auth.device_endpoints.WebAuthnManager") as mock_manager:
                    with patch("src.api.v1.auth.device_endpoints.UnitOfWork") as mock_uow:
                        # Setup mocks
                        mock_redis.return_value = AsyncMock()
                        
                        mock_store_instance = AsyncMock()
                        mock_store.return_value = mock_store_instance
                        mock_store_instance.retrieve_challenge.return_value = "test-challenge"
                        
                        mock_manager_instance = AsyncMock()
                        mock_manager.return_value = mock_manager_instance
                        mock_manager_instance.verify_registration.return_value = VerificationResult(
                            verified=True,
                            public_key="public-key-data",
                            sign_count=0,
                            attestation_type="none",
                            attestation_data={},
                            aaguid=None
                        )
                        mock_manager_instance.generate_device_name.return_value = "Chrome on Windows"
                        
                        mock_device = MagicMock()
                        mock_device.id = uuid4()
                        mock_device.device_name = "Chrome on Windows"
                        mock_device.trust_score = 50.0
                        
                        mock_repo = AsyncMock()
                        mock_repo.create.return_value = mock_device
                        
                        mock_uow_instance = AsyncMock()
                        mock_uow.return_value.__aenter__.return_value = mock_uow_instance
                        
                        with patch("src.api.v1.auth.device_endpoints.DeviceRepository") as mock_repo_class:
                            with patch("src.api.v1.auth.device_endpoints.calculate_trust_score") as mock_trust:
                                mock_repo_class.return_value = mock_repo
                                mock_trust.return_value = 50
                                
                                # Call function
                                result = await complete_device_registration(
                                    request=mock_request,
                                    verification=verification,
                                    current_user=mock_user,
                                    session=mock_session
                                )
                                
                                # Assertions
                                assert result.device_id == mock_device.id
                                assert result.device_name == "Chrome on Windows"
                                assert result.trust_level == 50
                                mock_repo.create.assert_called_once()
                                mock_uow_instance.commit.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_complete_registration_expired_challenge(self, mock_user, mock_request, mock_session):
        """Test registration with expired challenge."""
        verification = DeviceRegistrationVerification(
            id="new-credential-id",
            raw_id="new-credential-id",
            response=RegistrationResponse(
                client_data_json="fake-data",
                attestation_object="fake-attestation"
            ),
            type="public-key"
        )
        
        with patch("src.api.v1.auth.device_endpoints.get_redis_client") as mock_redis:
            with patch("src.api.v1.auth.device_endpoints.ChallengeStore") as mock_store:
                # Setup mocks
                mock_redis.return_value = AsyncMock()
                mock_store_instance = AsyncMock()
                mock_store.return_value = mock_store_instance
                mock_store_instance.retrieve_challenge.return_value = None  # No challenge found
                
                # Call function and expect exception
                with pytest.raises(HTTPException) as exc_info:
                    await complete_device_registration(
                        request=mock_request,
                        verification=verification,
                        current_user=mock_user,
                        session=mock_session
                    )
                
                assert exc_info.value.status_code == status.HTTP_400_BAD_REQUEST
                assert "expired" in str(exc_info.value.detail)


class TestListUserDevices:
    """Test device listing."""
    
    @pytest.mark.asyncio
    async def test_list_devices_success(self, mock_user, mock_device, mock_request, mock_session):
        """Test successful device listing."""
        with patch("src.api.v1.auth.device_endpoints.UnitOfWork") as mock_uow:
            mock_repo = AsyncMock()
            mock_repo.get_user_devices.return_value = [mock_device]
            
            mock_uow_instance = AsyncMock()
            mock_uow.return_value.__aenter__.return_value = mock_uow_instance
            
            with patch("src.api.v1.auth.device_endpoints.DeviceRepository") as mock_repo_class:
                mock_repo_class.return_value = mock_repo
                
                # Call function
                result = await list_user_devices(
                    current_user=mock_user,
                    session=mock_session,
                    request=mock_request
                )
                
                # Assertions
                assert result.total == 1
                assert len(result.devices) == 1
                assert result.devices[0].id == mock_device.id
                assert result.devices[0].name == mock_device.device_name
                mock_repo.get_user_devices.assert_called_once_with(mock_user.id)


class TestUpdateDevice:
    """Test device updates."""
    
    @pytest.mark.asyncio
    async def test_update_device_name(self, mock_user, mock_device, mock_session):
        """Test updating device name."""
        device_id = mock_device.id
        mock_device.user_id = mock_user.id
        update_request = DeviceUpdateRequest(name="New Device Name")
        
        with patch("src.api.v1.auth.device_endpoints.UnitOfWork") as mock_uow:
            mock_repo = AsyncMock()
            mock_repo.get_by_id.return_value = mock_device
            mock_repo.update.return_value = mock_device
            
            mock_uow_instance = AsyncMock()
            mock_uow.return_value.__aenter__.return_value = mock_uow_instance
            
            with patch("src.api.v1.auth.device_endpoints.DeviceRepository") as mock_repo_class:
                mock_repo_class.return_value = mock_repo
                
                # Call function
                result = await update_device(
                    device_id=device_id,
                    update_request=update_request,
                    current_user=mock_user,
                    session=mock_session
                )
                
                # Assertions
                assert result.id == device_id
                mock_repo.update.assert_called_once_with(
                    device_id,
                    {"device_name": "New Device Name"}
                )
    
    @pytest.mark.asyncio
    async def test_update_device_not_found(self, mock_user, mock_session):
        """Test updating non-existent device."""
        device_id = uuid4()
        update_request = DeviceUpdateRequest(name="New Name")
        
        with patch("src.api.v1.auth.device_endpoints.UnitOfWork") as mock_uow:
            mock_repo = AsyncMock()
            mock_repo.get_by_id.return_value = None
            
            mock_uow_instance = AsyncMock()
            mock_uow.return_value.__aenter__.return_value = mock_uow_instance
            
            with patch("src.api.v1.auth.device_endpoints.DeviceRepository") as mock_repo_class:
                mock_repo_class.return_value = mock_repo
                
                # Call function and expect exception
                with pytest.raises(HTTPException) as exc_info:
                    await update_device(
                        device_id=device_id,
                        update_request=update_request,
                        current_user=mock_user,
                        session=mock_session
                    )
                
                assert exc_info.value.status_code == status.HTTP_404_NOT_FOUND


class TestDeleteDevice:
    """Test device deletion."""
    
    @pytest.mark.asyncio
    async def test_delete_device_success(self, mock_user, mock_device, mock_request, mock_session):
        """Test successful device deletion."""
        device_id = mock_device.id
        mock_device.user_id = mock_user.id
        
        # Create another device so user has 2 devices
        another_device = MagicMock()
        another_device.id = uuid4()
        
        with patch("src.api.v1.auth.device_endpoints.UnitOfWork") as mock_uow:
            mock_repo = AsyncMock()
            mock_repo.get_user_devices.return_value = [mock_device, another_device]
            mock_repo.delete.return_value = None
            
            mock_uow_instance = AsyncMock()
            mock_uow.return_value.__aenter__.return_value = mock_uow_instance
            
            with patch("src.api.v1.auth.device_endpoints.DeviceRepository") as mock_repo_class:
                mock_repo_class.return_value = mock_repo
                
                # Call function
                await delete_device(
                    device_id=device_id,
                    current_user=mock_user,
                    session=mock_session,
                    request=mock_request
                )
                
                # Assertions
                mock_repo.delete.assert_called_once_with(device_id)
                mock_uow_instance.commit.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_delete_last_device_fails(self, mock_user, mock_device, mock_request, mock_session):
        """Test that deleting the last device fails."""
        device_id = mock_device.id
        mock_device.user_id = mock_user.id
        
        with patch("src.api.v1.auth.device_endpoints.UnitOfWork") as mock_uow:
            mock_repo = AsyncMock()
            mock_repo.get_user_devices.return_value = [mock_device]  # Only one device
            
            mock_uow_instance = AsyncMock()
            mock_uow.return_value.__aenter__.return_value = mock_uow_instance
            
            with patch("src.api.v1.auth.device_endpoints.DeviceRepository") as mock_repo_class:
                mock_repo_class.return_value = mock_repo
                
                # Call function and expect exception
                with pytest.raises(HTTPException) as exc_info:
                    await delete_device(
                        device_id=device_id,
                        current_user=mock_user,
                        session=mock_session,
                        request=mock_request
                    )
                
                assert exc_info.value.status_code == status.HTTP_400_BAD_REQUEST
                assert "last registered device" in str(exc_info.value.detail)