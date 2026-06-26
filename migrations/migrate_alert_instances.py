#!/usr/bin/env python3
"""
Migration script to add CASCADE delete to alert_instances and alert_logs tables.
This fixes the IntegrityError when deleting certificates.

For SQLite, we need to recreate the tables with the new foreign key constraints.
"""

import os
import sys
from datetime import datetime

# Add the app directory to the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from flask import Flask
from config import Config
from models import db

def migrate():
    """Apply migration to add CASCADE delete constraints."""
    app = Flask(__name__)
    app.config.from_object(Config)
    
    db.init_app(app)
    
    with app.app_context():
        print("Starting migration...")
        print(f"Database URI: {app.config['SQLALCHEMY_DATABASE_URI']}")
        
        # Check if we're using SQLite
        if 'sqlite' in app.config['SQLALCHEMY_DATABASE_URI'].lower():
            print("\nDetected SQLite database. Recreating tables with CASCADE constraints...")
            
            # Backup data from alert_instances
            print("1. Backing up alert_instances...")
            backup_instances = db.session.execute(
                db.text("SELECT * FROM alert_instances")
            ).fetchall()
            print(f"   Backed up {len(backup_instances)} alert instances")
            
            # Backup data from alert_logs
            print("2. Backing up alert_logs...")
            backup_logs = db.session.execute(
                db.text("SELECT * FROM alert_logs")
            ).fetchall()
            print(f"   Backed up {len(backup_logs)} alert logs")
            
            # Drop and recreate alert_instances table
            print("3. Recreating alert_instances table...")
            db.session.execute(db.text("DROP TABLE IF EXISTS alert_instances"))
            db.session.execute(db.text("""
                CREATE TABLE alert_instances (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    certificate_id INTEGER NOT NULL,
                    alert_rule_id INTEGER NOT NULL,
                    state VARCHAR(20) NOT NULL DEFAULT 'firing',
                    first_fired_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    last_fired_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    paused_at DATETIME,
                    resumed_at DATETIME,
                    resolved_at DATETIME,
                    acknowledged_at DATETIME,
                    paused_by VARCHAR(80),
                    acknowledged_by VARCHAR(80),
                    notes TEXT,
                    FOREIGN KEY (certificate_id) REFERENCES certificates(id) ON DELETE CASCADE,
                    FOREIGN KEY (alert_rule_id) REFERENCES alert_rules(id) ON DELETE CASCADE
                )
            """))
            db.session.execute(db.text(
                "CREATE INDEX idx_cert_rule_state ON alert_instances(certificate_id, alert_rule_id, state)"
            ))
            db.session.commit()
            print("   ✓ alert_instances table recreated")
            
            # Drop and recreate alert_logs table
            print("4. Recreating alert_logs table...")
            db.session.execute(db.text("DROP TABLE IF EXISTS alert_logs"))
            db.session.execute(db.text("""
                CREATE TABLE alert_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    certificate_id INTEGER NOT NULL,
                    alert_rule_id INTEGER,
                    channel_type VARCHAR(50),
                    message TEXT,
                    status VARCHAR(20) DEFAULT 'sent',
                    error_message TEXT,
                    sent_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (certificate_id) REFERENCES certificates(id) ON DELETE CASCADE,
                    FOREIGN KEY (alert_rule_id) REFERENCES alert_rules(id) ON DELETE CASCADE
                )
            """))
            db.session.commit()
            print("   ✓ alert_logs table recreated")
            
            # Restore alert_instances data
            if backup_instances:
                print("5. Restoring alert_instances data...")
                for row in backup_instances:
                    try:
                        db.session.execute(db.text("""
                            INSERT INTO alert_instances 
                            (id, certificate_id, alert_rule_id, state, first_fired_at, last_fired_at,
                             paused_at, resumed_at, resolved_at, acknowledged_at, paused_by, acknowledged_by, notes)
                            VALUES (:id, :cert_id, :rule_id, :state, :first_fired, :last_fired,
                                    :paused, :resumed, :resolved, :acked, :paused_by, :acked_by, :notes)
                        """), {
                            'id': row[0], 'cert_id': row[1], 'rule_id': row[2], 'state': row[3],
                            'first_fired': row[4], 'last_fired': row[5], 'paused': row[6],
                            'resumed': row[7], 'resolved': row[8], 'acked': row[9],
                            'paused_by': row[10], 'acked_by': row[11], 'notes': row[12]
                        })
                    except Exception as e:
                        print(f"   Warning: Could not restore instance {row[0]}: {e}")
                db.session.commit()
                print(f"   ✓ Restored alert_instances data")
            
            # Restore alert_logs data
            if backup_logs:
                print("6. Restoring alert_logs data...")
                for row in backup_logs:
                    try:
                        db.session.execute(db.text("""
                            INSERT INTO alert_logs 
                            (id, certificate_id, alert_rule_id, channel_type, message, status, error_message, sent_at)
                            VALUES (:id, :cert_id, :rule_id, :channel, :msg, :status, :error, :sent)
                        """), {
                            'id': row[0], 'cert_id': row[1], 'rule_id': row[2], 'channel': row[3],
                            'msg': row[4], 'status': row[5], 'error': row[6], 'sent': row[7]
                        })
                    except Exception as e:
                        print(f"   Warning: Could not restore log {row[0]}: {e}")
                db.session.commit()
                print(f"   ✓ Restored alert_logs data")
            
            print("\n✅ Migration completed successfully!")
            print("   Certificates can now be deleted without IntegrityError.")
            
        else:
            # For MariaDB/MySQL, we can alter the foreign keys
            print("\nDetected MariaDB/MySQL database. Altering foreign key constraints...")
            
            try:
                # Drop existing foreign keys and recreate with CASCADE
                db.session.execute(db.text("""
                    ALTER TABLE alert_instances 
                    DROP FOREIGN KEY alert_instances_ibfk_1,
                    DROP FOREIGN KEY alert_instances_ibfk_2,
                    ADD CONSTRAINT alert_instances_ibfk_1 
                        FOREIGN KEY (certificate_id) REFERENCES certificates(id) ON DELETE CASCADE,
                    ADD CONSTRAINT alert_instances_ibfk_2 
                        FOREIGN KEY (alert_rule_id) REFERENCES alert_rules(id) ON DELETE CASCADE
                """))
                
                db.session.execute(db.text("""
                    ALTER TABLE alert_logs 
                    DROP FOREIGN KEY alert_logs_ibfk_1,
                    DROP FOREIGN KEY alert_logs_ibfk_2,
                    ADD CONSTRAINT alert_logs_ibfk_1 
                        FOREIGN KEY (certificate_id) REFERENCES certificates(id) ON DELETE CASCADE,
                    ADD CONSTRAINT alert_logs_ibfk_2 
                        FOREIGN KEY (alert_rule_id) REFERENCES alert_rules(id) ON DELETE CASCADE
                """))
                
                db.session.commit()
                print("✅ Migration completed successfully!")
                
            except Exception as e:
                print(f"⚠️  Migration failed: {e}")
                print("You may need to manually adjust the foreign key constraint names.")
                db.session.rollback()
                return 1
        
        return 0

if __name__ == '__main__':
    sys.exit(migrate())
