#!/usr/bin/env python3
"""
Seed script for permission system.
Creates system roles and permissions for all tenants.
"""

import asyncio
import os
import sys
from pathlib import Path

# Add project root to Python path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from sqlalchemy.orm import Session
from src.infrastructure.database.session import get_db
from src.core.auth.permission_service import PermissionService
from src.infrastructure.database.models.tenant import Tenant
from src.core.logging import get_logger

logger = get_logger(__name__)


async def seed_permissions():
    """Seed permissions for all existing tenants."""
    logger.info("Starting permission system seeding")
    
    # Get database session
    db_generator = get_db()
    db: Session = next(db_generator)
    
    try:
        service = PermissionService(db)
        
        # Get all tenants
        tenants = db.query(Tenant).filter(Tenant.is_active == True).all()
        
        if not tenants:
            logger.warning("No active tenants found")
            return
        
        logger.info(f"Found {len(tenants)} active tenants")
        
        # Create system roles for each tenant
        for tenant in tenants:
            logger.info(f"Creating system roles for tenant: {tenant.name} ({tenant.id})")
            
            try:
                roles = await service.create_system_roles(tenant.id)
                logger.info(f"Created {len(roles)} system roles for tenant {tenant.name}")
                
                for role in roles:
                    logger.debug(f"Created role: {role.name} (system={role.is_system})")
                    
            except Exception as e:
                logger.error(f"Failed to create roles for tenant {tenant.name}: {e}")
                # Continue with other tenants
                continue
        
        logger.info("Permission system seeding completed successfully")
        
    except Exception as e:
        logger.error(f"Failed to seed permissions: {e}")
        raise
    finally:
        db.close()


if __name__ == "__main__":
    asyncio.run(seed_permissions())