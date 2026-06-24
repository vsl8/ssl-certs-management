"""
Database Migration: Add theme column to users table

This script adds the theme column to the users table for existing databases.
Run this script if you have an existing database without the theme column.

Usage:
    python migrate_add_theme.py
"""

import os
import sys
from sqlalchemy import create_engine, text
from config import Config

def migrate_database():
    """Add theme column to users table if it doesn't exist."""
    print("Starting database migration: Add theme column to users table")
    
    config = Config()
    engine = create_engine(config.SQLALCHEMY_DATABASE_URI)
    
    try:
        with engine.connect() as conn:
            # Check if theme column already exists
            if config.DB_TYPE == 'sqlite':
                result = conn.execute(text("PRAGMA table_info(users)")).fetchall()
                columns = [row[1] for row in result]
            else:  # mariadb/mysql
                result = conn.execute(text(
                    "SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS "
                    "WHERE TABLE_NAME = 'users' AND TABLE_SCHEMA = DATABASE()"
                )).fetchall()
                columns = [row[0] for row in result]
            
            if 'theme' in columns:
                print("✓ Theme column already exists. No migration needed.")
                return
            
            print("Adding theme column to users table...")
            
            # Add the theme column
            if config.DB_TYPE == 'sqlite':
                conn.execute(text(
                    "ALTER TABLE users ADD COLUMN theme VARCHAR(50) NOT NULL DEFAULT 'default'"
                ))
            else:  # mariadb/mysql
                conn.execute(text(
                    "ALTER TABLE users ADD COLUMN theme VARCHAR(50) NOT NULL DEFAULT 'default'"
                ))
            
            conn.commit()
            print("✓ Theme column added successfully!")
            print("✓ All existing users will use the 'default' theme.")
            
    except Exception as e:
        print(f"✗ Migration failed: {e}")
        sys.exit(1)
    finally:
        engine.dispose()

if __name__ == '__main__':
    migrate_database()
