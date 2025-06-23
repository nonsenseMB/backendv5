"""
LLM provider and API key repository implementations.
"""
from typing import Optional, List
from uuid import UUID
from datetime import datetime

from sqlalchemy import select, and_, or_
from sqlalchemy.orm import selectinload

from infrastructure.database.models.llm import LLMProvider, LLMAPIKey
from infrastructure.database.repositories.base import BaseRepository, TenantAwareRepository


class LLMProviderRepository(TenantAwareRepository[LLMProvider]):
    """Repository for LLMProvider model."""
    
    async def get_active_providers(self) -> List[LLMProvider]:
        """Get all active LLM providers for the tenant."""
        return await self.get_multi(filters={'is_active': True})
    
    async def get_by_type(self, provider_type: str) -> Optional[LLMProvider]:
        """Get provider by type within the tenant."""
        stmt = select(LLMProvider).where(
            and_(
                LLMProvider.tenant_id == self.tenant_id,
                LLMProvider.provider_type == provider_type
            )
        )
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()
    
    async def get_default_provider(self) -> Optional[LLMProvider]:
        """Get the default provider for the tenant."""
        stmt = select(LLMProvider).where(
            and_(
                LLMProvider.tenant_id == self.tenant_id,
                LLMProvider.is_default == True,
                LLMProvider.is_active == True
            )
        )
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()
    
    async def set_default_provider(self, provider_id: UUID) -> Optional[LLMProvider]:
        """Set a provider as default (unsets other defaults)."""
        # First, unset all current defaults
        stmt = select(LLMProvider).where(
            and_(
                LLMProvider.tenant_id == self.tenant_id,
                LLMProvider.is_default == True
            )
        )
        result = await self.session.execute(stmt)
        current_defaults = result.scalars().all()
        
        for provider in current_defaults:
            await self.update(provider.id, is_default=False)
        
        # Set the new default
        return await self.update(provider_id, is_default=True)
    
    async def update_usage(
        self,
        provider_id: UUID,
        tokens_used: int,
        cost: float = 0.0
    ) -> Optional[LLMProvider]:
        """Update usage statistics for a provider."""
        provider = await self.get(provider_id)
        if not provider:
            return None
        
        return await self.update(
            provider_id,
            total_tokens_used=provider.total_tokens_used + tokens_used,
            total_cost=provider.total_cost + cost,
            last_used_at=datetime.utcnow()
        )


class LLMAPIKeyRepository(BaseRepository[LLMAPIKey]):
    """Repository for LLMAPIKey model."""
    
    async def get_provider_keys(
        self,
        provider_id: UUID,
        only_active: bool = True
    ) -> List[LLMAPIKey]:
        """Get all API keys for a provider."""
        filters = {'provider_id': provider_id}
        if only_active:
            filters['is_active'] = True
        
        return await self.get_multi(filters=filters)
    
    async def get_active_key_for_provider(self, provider_id: UUID) -> Optional[LLMAPIKey]:
        """Get an active API key for a provider (for load balancing)."""
        keys = await self.get_provider_keys(provider_id, only_active=True)
        
        if not keys:
            return None
        
        # Simple strategy: return the least used key
        return min(keys, key=lambda k: k.total_requests)
    
    async def get_by_hint(self, key_hint: str) -> Optional[LLMAPIKey]:
        """Get API key by its hint."""
        return await self.get_by(key_hint=key_hint)
    
    async def create_api_key(
        self,
        provider_id: UUID,
        key_name: str,
        encrypted_key: str,
        created_by: UUID,
        key_hint: str = None,
        encryption_key_id: str = None
    ) -> LLMAPIKey:
        """Create a new API key."""
        return await self.create(
            provider_id=provider_id,
            key_name=key_name,
            encrypted_key=encrypted_key,
            created_by=created_by,
            key_hint=key_hint,
            encryption_key_id=encryption_key_id,
            is_active=True
        )
    
    async def update_key_usage(
        self,
        key_id: UUID,
        tokens_used: int,
        cost: float = 0.0
    ) -> Optional[LLMAPIKey]:
        """Update usage statistics for an API key."""
        key = await self.get(key_id)
        if not key:
            return None
        
        return await self.update(
            key_id,
            total_requests=key.total_requests + 1,
            total_tokens=key.total_tokens + tokens_used,
            total_cost=key.total_cost + cost,
            last_used_at=datetime.utcnow()
        )
    
    async def check_rate_limits(self, key_id: UUID) -> dict:
        """Check if an API key has exceeded its rate limits."""
        key = await self.get(key_id)
        if not key:
            return {'allowed': False, 'reason': 'Key not found'}
        
        if not key.is_active:
            return {'allowed': False, 'reason': 'Key is inactive'}
        
        # Here you would implement actual rate limit checking
        # This is a simplified version
        limits_ok = True
        reason = None
        
        # For now, just check if key is active
        if not key.is_active:
            limits_ok = False
            reason = 'API key is inactive'
        
        return {
            'allowed': limits_ok,
            'reason': reason,
            'usage': {
                'total_requests': key.total_requests,
                'total_tokens': key.total_tokens,
                'total_cost': float(key.total_cost)
            }
        }
    
    async def rotate_key(
        self,
        key_id: UUID,
        new_encrypted_key: str,
        new_key_hint: str = None
    ) -> Optional[LLMAPIKey]:
        """Rotate an API key."""
        update_data = {
            'encrypted_key': new_encrypted_key
        }
        if new_key_hint:
            update_data['key_hint'] = new_key_hint
        
        return await self.update(key_id, **update_data)