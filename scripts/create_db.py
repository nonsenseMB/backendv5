#!/usr/bin/env python3
"""
Create the database if it doesn't exist.
"""
import psycopg2
from psycopg2 import sql
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT


def create_database():
    """Create the database if it doesn't exist."""
    # Connection parameters
    conn_params = {
        'host': 'localhost',
        'port': 5432,
        'user': 'nai_backend',
        'password': 'c6PuT861ajXnuMQr5WLykmHeNtZDeRBm@Y1fY',
        'database': 'postgres'  # Connect to default database first
    }
    
    try:
        # Connect to PostgreSQL
        conn = psycopg2.connect(**conn_params)
        conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
        cursor = conn.cursor()
        
        # Check if database exists
        cursor.execute(
            "SELECT 1 FROM pg_database WHERE datname = %s",
            ('nai_backend_v5',)
        )
        exists = cursor.fetchone()
        
        if not exists:
            # Create database
            cursor.execute(
                sql.SQL("CREATE DATABASE {}").format(
                    sql.Identifier('nai_backend_v5')
                )
            )
            print("✅ Database 'nai_backend_v5' created successfully!")
        else:
            print("ℹ️  Database 'nai_backend_v5' already exists.")
        
        # Close connection
        cursor.close()
        conn.close()
        
        return True
        
    except Exception as e:
        print(f"❌ Error creating database: {e}")
        return False


if __name__ == "__main__":
    print("Creating database...")
    if create_database():
        print("\n✅ Database setup complete!")
        print("\nYou can now run:")
        print("  python scripts/check_db.py")
    else:
        print("\n❌ Database creation failed.")