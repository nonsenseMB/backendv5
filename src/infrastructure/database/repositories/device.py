"""Repository for device management."""
from datetime import datetime
from typing import List, Optional
from uuid import UUID

from sqlalchemy import and_, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload

from src.infrastructure.database.models.auth import UserDevice
from src.infrastructure.database.repositories.base import BaseRepository
from src.core.logging import get_logger

logger = get_logger(__name__)


class DeviceRepository(BaseRepository[UserDevice]):
    """Repository for managing user authentication devices."""
    
    def __init__(
        self,
        model: type[UserDevice],
        session: AsyncSession,
        tenant_id: Optional[UUID] = None
    ):
        """Initialize device repository."""
        super().__init__(model, session, tenant_id)
    
    async def get_user_devices(
        self,
        user_id: UUID,
        active_only: bool = True
    ) -> List[UserDevice]:
        """
        Get all devices for a user.
        
        Args:
            user_id: User ID
            active_only: Whether to return only active devices
            
        Returns:
            List of user devices
        """
        try:
            query = select(self.model).where(
                self.model.user_id == user_id
            )
            
            if active_only:
                query = query.where(self.model.is_active == True)
            
            # Order by last used, then created
            query = query.order_by(
                self.model.last_used_at.desc().nullslast(),
                self.model.created_at.desc()
            )
            
            result = await self.session.execute(query)
            devices = result.scalars().all()
            
            logger.debug(
                "Retrieved user devices",
                user_id=str(user_id),
                device_count=len(devices),
                active_only=active_only
            )
            
            return devices
            
        except Exception as e:
            logger.error(
                "Failed to get user devices",
                user_id=str(user_id),
                error=str(e),
                exc_info=True
            )
            raise
    
    async def get_by_credential_id(
        self,
        credential_id: str
    ) -> Optional[UserDevice]:
        """
        Get device by credential ID.
        
        Args:
            credential_id: WebAuthn credential ID
            
        Returns:
            Device if found, None otherwise
        """
        try:
            query = select(self.model).where(
                and_(
                    self.model.credential_id == credential_id,
                    self.model.is_active == True
                )
            ).options(joinedload(self.model.user))
            
            result = await self.session.execute(query)
            device = result.scalar_one_or_none()
            
            if device:
                logger.debug(
                    "Found device by credential",
                    credential_id=credential_id[:20] + "...",
                    device_id=str(device.id)
                )
            
            return device
            
        except Exception as e:
            logger.error(
                "Failed to get device by credential",
                credential_id=credential_id[:20] + "...",
                error=str(e),
                exc_info=True
            )
            raise
    
    async def get_by_device_id(
        self,
        device_id: str
    ) -> Optional[UserDevice]:
        """
        Get device by device ID.
        
        Args:
            device_id: Device identifier
            
        Returns:
            Device if found, None otherwise
        """
        try:
            query = select(self.model).where(
                self.model.device_id == device_id
            )
            
            result = await self.session.execute(query)
            device = result.scalar_one_or_none()
            
            return device
            
        except Exception as e:
            logger.error(
                "Failed to get device by device ID",
                device_id=device_id,
                error=str(e),
                exc_info=True
            )
            raise
    
    async def update_last_used(
        self,
        device_id: UUID,
        increment_counter: bool = True,
        new_sign_count: Optional[int] = None
    ) -> UserDevice:
        """
        Update device last used timestamp and optionally increment counter.
        
        Args:
            device_id: Device ID
            increment_counter: Whether to increment use count
            new_sign_count: New sign count for replay protection
            
        Returns:
            Updated device
        """
        try:
            # Build update statement
            stmt = update(self.model).where(
                self.model.id == device_id
            ).values(
                last_used_at=datetime.utcnow(),
                updated_at=datetime.utcnow()
            )
            
            if increment_counter:
                stmt = stmt.values(
                    use_count=self.model.use_count + 1
                )
            
            if new_sign_count is not None:
                stmt = stmt.values(
                    sign_count=new_sign_count
                )
            
            await self.session.execute(stmt)
            
            # Fetch updated device
            device = await self.get_by_id(device_id)
            
            logger.info(
                "Updated device last used",
                device_id=str(device_id),
                increment_counter=increment_counter,
                new_sign_count=new_sign_count
            )
            
            return device
            
        except Exception as e:
            logger.error(
                "Failed to update device last used",
                device_id=str(device_id),
                error=str(e),
                exc_info=True
            )
            raise
    
    async def update_trust_score(
        self,
        device_id: UUID,
        trust_score: float
    ) -> UserDevice:
        """
        Update device trust score.
        
        Args:
            device_id: Device ID
            trust_score: New trust score (0.0 - 100.0)
            
        Returns:
            Updated device
        """
        try:
            # Ensure trust score is within bounds
            trust_score = max(0.0, min(100.0, trust_score))
            
            # Determine if device should be trusted
            is_trusted = trust_score >= 80.0
            
            # Update device
            device = await self.update(device_id, {
                "trust_score": trust_score,
                "is_trusted": is_trusted
            })
            
            logger.info(
                "Updated device trust score",
                device_id=str(device_id),
                trust_score=trust_score,
                is_trusted=is_trusted
            )
            
            return device
            
        except Exception as e:
            logger.error(
                "Failed to update device trust score",
                device_id=str(device_id),
                error=str(e),
                exc_info=True
            )
            raise
    
    async def deactivate_device(
        self,
        device_id: UUID
    ) -> UserDevice:
        """
        Deactivate a device (soft delete).
        
        Args:
            device_id: Device ID
            
        Returns:
            Deactivated device
        """
        try:
            device = await self.update(device_id, {
                "is_active": False,
                "updated_at": datetime.utcnow()
            })
            
            logger.info(
                "Deactivated device",
                device_id=str(device_id)
            )
            
            return device
            
        except Exception as e:
            logger.error(
                "Failed to deactivate device",
                device_id=str(device_id),
                error=str(e),
                exc_info=True
            )
            raise
    
    async def count_user_devices(
        self,
        user_id: UUID,
        active_only: bool = True
    ) -> int:
        """
        Count devices for a user.
        
        Args:
            user_id: User ID
            active_only: Whether to count only active devices
            
        Returns:
            Device count
        """
        try:
            query = select(func.count(self.model.id)).where(
                self.model.user_id == user_id
            )
            
            if active_only:
                query = query.where(self.model.is_active == True)
            
            result = await self.session.execute(query)
            count = result.scalar() or 0
            
            return count
            
        except Exception as e:
            logger.error(
                "Failed to count user devices",
                user_id=str(user_id),
                error=str(e),
                exc_info=True
            )
            raise
    
    async def get_trusted_devices(
        self,
        user_id: UUID
    ) -> List[UserDevice]:
        """
        Get all trusted devices for a user.
        
        Args:
            user_id: User ID
            
        Returns:
            List of trusted devices
        """
        try:
            query = select(self.model).where(
                and_(
                    self.model.user_id == user_id,
                    self.model.is_active == True,
                    self.model.is_trusted == True
                )
            ).order_by(
                self.model.trust_score.desc(),
                self.model.last_used_at.desc().nullslast()
            )
            
            result = await self.session.execute(query)
            devices = result.scalars().all()
            
            logger.debug(
                "Retrieved trusted devices",
                user_id=str(user_id),
                device_count=len(devices)
            )
            
            return devices
            
        except Exception as e:
            logger.error(
                "Failed to get trusted devices",
                user_id=str(user_id),
                error=str(e),
                exc_info=True
            )
            raise
    
    async def cleanup_inactive_devices(
        self,
        user_id: UUID,
        days_inactive: int = 90
    ) -> int:
        """
        Clean up devices that haven't been used in specified days.
        
        Args:
            user_id: User ID
            days_inactive: Number of days of inactivity
            
        Returns:
            Number of devices deactivated
        """
        try:
            # Calculate cutoff date
            from datetime import timedelta
            cutoff_date = datetime.utcnow() - timedelta(days=days_inactive)
            
            # Find inactive devices
            query = select(self.model).where(
                and_(
                    self.model.user_id == user_id,
                    self.model.is_active == True,
                    self.model.last_used_at < cutoff_date
                )
            )
            
            result = await self.session.execute(query)
            devices = result.scalars().all()
            
            # Deactivate each device
            deactivated_count = 0
            for device in devices:
                await self.deactivate_device(device.id)
                deactivated_count += 1
            
            logger.info(
                "Cleaned up inactive devices",
                user_id=str(user_id),
                days_inactive=days_inactive,
                deactivated_count=deactivated_count
            )
            
            return deactivated_count
            
        except Exception as e:
            logger.error(
                "Failed to cleanup inactive devices",
                user_id=str(user_id),
                error=str(e),
                exc_info=True
            )
            raise