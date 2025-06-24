#!/usr/bin/env python3
"""
Check database connection and create initial migration.
"""
import asyncio
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from sqlalchemy import create_engine, text
from sqlalchemy.ext.asyncio import create_async_engine


async def check_connection():
    """Test database connection."""
    # Database URL - adjust if needed
    DATABASE_URL = "postgresql+asyncpg://nai_backend:c6PuT861ajXnuMQr5WLykmHeNtZDeRBm%40Y1fY@localhost:5432/nai_backend_v5"
    
    try:
        # Create async engine
        engine = create_async_engine(DATABASE_URL, echo=True)
        
        # Test connection
        async with engine.connect() as conn:
            result = await conn.execute(text("SELECT 1"))
            print("✅ Database connection successful!")
            
        await engine.dispose()
        return True
        
    except Exception as e:
        print(f"❌ Database connection failed: {e}")
        return False


def check_sync_connection():
    """Test synchronous database connection for Alembic."""
    DATABASE_URL = "postgresql://nai_backend:c6PuT861ajXnuMQr5WLykmHeNtZDeRBm%40Y1fY@localhost:5432/nai_backend_v5"
    
    try:
        engine = create_engine(DATABASE_URL)
        with engine.connect() as conn:
            result = conn.execute(text("SELECT 1"))
            print("✅ Sync database connection successful!")
        return True
    except Exception as e:
        print(f"❌ Sync database connection failed: {e}")
        return False


if __name__ == "__main__":
    print("Checking database connections...")
    
    # Check sync connection (for Alembic)
    sync_ok = check_sync_connection()
    
    # Check async connection (for application)
    async_ok = asyncio.run(check_connection())
    
    if sync_ok and async_ok:
        print("\n✅ All database connections are working!")
        print("\nYou can now run:")
        print("  alembic revision --autogenerate -m 'Initial schema'")
        print("  alembic upgrade head")
    else:
        print("\n❌ Please check your database configuration.")
        sys.exit(1)