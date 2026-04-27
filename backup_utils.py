"""
Backup utilities for SSL Certificate Manager.
Supports certificate backup (ZIP) and database export (SQL).
"""

import os
import zipfile
import glob
from datetime import datetime
from logger import get_logger

log = get_logger('backup')

# Default backup configuration
DEFAULT_BACKUP_PATH = '/etc/pki/tls/backup'
MAX_BACKUPS = 5


def get_backup_path():
    """Get the backup directory path from settings or use default."""
    try:
        from flask import current_app
        from models import Setting
        setting = Setting.query.filter_by(key='backup_path').first()
        if setting and setting.value:
            return setting.value
    except Exception:
        pass
    return DEFAULT_BACKUP_PATH


def ensure_backup_dir():
    """Ensure the backup directory exists."""
    backup_path = get_backup_path()
    os.makedirs(backup_path, exist_ok=True)
    return backup_path


def get_timestamp():
    """Get current timestamp for backup filenames."""
    return datetime.now().strftime('%Y-%m-%d_%H-%M-%S')


def cleanup_old_backups(backup_type='certs'):
    """
    Remove old backups keeping only the most recent MAX_BACKUPS.
    
    Args:
        backup_type: 'certs' or 'db'
    """
    backup_path = get_backup_path()
    
    if backup_type == 'certs':
        pattern = os.path.join(backup_path, 'certs_backup_*.zip')
    else:
        pattern = os.path.join(backup_path, 'db_backup_*.sql')
    
    # Get all backup files sorted by modification time (oldest first)
    backup_files = sorted(glob.glob(pattern), key=os.path.getmtime)
    
    # Remove old backups if we have more than MAX_BACKUPS
    while len(backup_files) > MAX_BACKUPS:
        oldest = backup_files.pop(0)
        try:
            os.remove(oldest)
            log.info('Removed old backup: %s', oldest)
        except Exception as e:
            log.warning('Failed to remove old backup %s: %s', oldest, e)
    
    return len(backup_files)


def backup_certificates():
    """
    Create a ZIP backup of all certificate files.
    
    Returns:
        dict: {'success': bool, 'message': str, 'filename': str, 'path': str}
    """
    from models import Certificate, Setting
    
    backup_path = ensure_backup_dir()
    timestamp = get_timestamp()
    filename = f'certs_backup_{timestamp}.zip'
    zip_path = os.path.join(backup_path, filename)
    
    try:
        # Get certificate storage path from settings
        cert_storage_setting = Setting.query.filter_by(key='cert_storage_path').first()
        cert_storage_path = cert_storage_setting.value if cert_storage_setting else '/etc/pki/tls/certs'
        
        # Get all certificates from database
        certificates = Certificate.query.all()
        
        if not certificates:
            return {
                'success': False,
                'message': 'No certificates found to backup.',
                'filename': None,
                'path': None
            }
        
        files_backed_up = 0
        files_missing = 0
        
        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            # Add a manifest file with backup info
            manifest = f"SSL Certificate Manager - Certificate Backup\n"
            manifest += f"Backup Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            manifest += f"Total Certificates in DB: {len(certificates)}\n"
            manifest += f"\n--- Certificate Files ---\n\n"
            
            for cert in certificates:
                if cert.file_path and os.path.exists(cert.file_path):
                    # Use relative path inside zip
                    arcname = os.path.basename(cert.file_path)
                    # Handle duplicates by adding cert ID
                    if arcname in [n.filename for n in zipf.namelist()]:
                        base, ext = os.path.splitext(arcname)
                        arcname = f"{base}_{cert.id}{ext}"
                    
                    zipf.write(cert.file_path, arcname)
                    manifest += f"- {arcname} (CN: {cert.common_name or 'N/A'})\n"
                    files_backed_up += 1
                else:
                    manifest += f"- MISSING: {cert.filename} (Path: {cert.file_path})\n"
                    files_missing += 1
            
            manifest += f"\n--- Summary ---\n"
            manifest += f"Files backed up: {files_backed_up}\n"
            manifest += f"Files missing: {files_missing}\n"
            
            zipf.writestr('MANIFEST.txt', manifest)
        
        # Cleanup old backups
        cleanup_old_backups('certs')
        
        log.info('Certificate backup created: %s (%d files)', filename, files_backed_up)
        
        return {
            'success': True,
            'message': f'Backup created successfully! {files_backed_up} certificates backed up.',
            'filename': filename,
            'path': zip_path,
            'files_backed_up': files_backed_up,
            'files_missing': files_missing
        }
        
    except Exception as e:
        log.error('Certificate backup failed: %s', str(e))
        # Clean up partial backup
        if os.path.exists(zip_path):
            try:
                os.remove(zip_path)
            except Exception:
                pass
        return {
            'success': False,
            'message': f'Backup failed: {str(e)}',
            'filename': None,
            'path': None
        }


def backup_database():
    """
    Create a SQL backup of the database.
    Supports both SQLite and MariaDB/MySQL.
    
    Returns:
        dict: {'success': bool, 'message': str, 'filename': str, 'path': str}
    """
    from flask import current_app
    from models import db, User, Certificate, AlertRule, NotificationChannel, AlertLog, Setting, CSRConfig, CSRRequest
    
    backup_path = ensure_backup_dir()
    timestamp = get_timestamp()
    filename = f'db_backup_{timestamp}.sql'
    sql_path = os.path.join(backup_path, filename)
    
    try:
        db_uri = current_app.config.get('SQLALCHEMY_DATABASE_URI', '')
        
        # Generate SQL dump
        sql_content = generate_sql_dump()
        
        with open(sql_path, 'w', encoding='utf-8') as f:
            f.write(sql_content)
        
        # Cleanup old backups
        cleanup_old_backups('db')
        
        log.info('Database backup created: %s', filename)
        
        return {
            'success': True,
            'message': 'Database backup created successfully!',
            'filename': filename,
            'path': sql_path
        }
        
    except Exception as e:
        log.error('Database backup failed: %s', str(e))
        # Clean up partial backup
        if os.path.exists(sql_path):
            try:
                os.remove(sql_path)
            except Exception:
                pass
        return {
            'success': False,
            'message': f'Database backup failed: {str(e)}',
            'filename': None,
            'path': None
        }


def generate_sql_dump():
    """
    Generate a MySQL/MariaDB compatible SQL dump from the database.
    Works with both SQLite and MariaDB backends.
    """
    from models import db, User, Certificate, AlertRule, NotificationChannel, AlertLog, Setting, CSRConfig, CSRRequest
    
    sql_lines = []
    
    # Header
    sql_lines.append('-- SSL Certificate Manager Database Backup')
    sql_lines.append(f'-- Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}')
    sql_lines.append('-- Compatible with MySQL/MariaDB')
    sql_lines.append('')
    sql_lines.append('SET FOREIGN_KEY_CHECKS=0;')
    sql_lines.append('SET SQL_MODE="NO_AUTO_VALUE_ON_ZERO";')
    sql_lines.append('')
    
    # Define tables and their models in order (respecting foreign keys)
    tables = [
        ('users', User),
        ('settings', Setting),
        ('notification_channels', NotificationChannel),
        ('alert_rules', AlertRule),
        ('certificates', Certificate),
        ('alert_logs', AlertLog),
        ('csr_configs', CSRConfig),
        ('csr_requests', CSRRequest),
    ]
    
    for table_name, model in tables:
        sql_lines.append(f'-- Table: {table_name}')
        sql_lines.append(f'-- ----------------------------')
        
        # Generate CREATE TABLE statement
        sql_lines.append(generate_create_table(table_name, model))
        sql_lines.append('')
        
        # Generate INSERT statements
        try:
            records = model.query.all()
            for record in records:
                insert_sql = generate_insert_statement(table_name, model, record)
                if insert_sql:
                    sql_lines.append(insert_sql)
        except Exception as e:
            sql_lines.append(f'-- Error exporting {table_name}: {str(e)}')
        
        sql_lines.append('')
    
    sql_lines.append('SET FOREIGN_KEY_CHECKS=1;')
    sql_lines.append('')
    sql_lines.append('-- End of backup')
    
    return '\n'.join(sql_lines)


def generate_create_table(table_name, model):
    """Generate CREATE TABLE statement for a model."""
    lines = [f'DROP TABLE IF EXISTS `{table_name}`;']
    lines.append(f'CREATE TABLE `{table_name}` (')
    
    columns = []
    primary_key = None
    
    for column in model.__table__.columns:
        col_def = f'  `{column.name}`'
        
        # Map SQLAlchemy types to MySQL types
        col_type = str(column.type)
        if 'INTEGER' in col_type.upper():
            col_def += ' INT'
        elif 'VARCHAR' in col_type.upper() or 'STRING' in col_type.upper():
            length = getattr(column.type, 'length', 255) or 255
            col_def += f' VARCHAR({length})'
        elif 'TEXT' in col_type.upper():
            col_def += ' TEXT'
        elif 'BOOLEAN' in col_type.upper():
            col_def += ' TINYINT(1)'
        elif 'DATETIME' in col_type.upper():
            col_def += ' DATETIME'
        elif 'DATE' in col_type.upper():
            col_def += ' DATE'
        elif 'FLOAT' in col_type.upper() or 'REAL' in col_type.upper():
            col_def += ' FLOAT'
        else:
            col_def += ' VARCHAR(255)'
        
        if not column.nullable:
            col_def += ' NOT NULL'
        
        if column.primary_key:
            primary_key = column.name
            col_def += ' AUTO_INCREMENT'
        
        if column.default is not None and not callable(column.default.arg):
            default_val = column.default.arg
            if isinstance(default_val, bool):
                col_def += f' DEFAULT {1 if default_val else 0}'
            elif isinstance(default_val, (int, float)):
                col_def += f' DEFAULT {default_val}'
            elif isinstance(default_val, str):
                col_def += f" DEFAULT '{escape_sql_string(default_val)}'"
        
        columns.append(col_def)
    
    if primary_key:
        columns.append(f'  PRIMARY KEY (`{primary_key}`)')
    
    lines.append(',\n'.join(columns))
    lines.append(') ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;')
    
    return '\n'.join(lines)


def generate_insert_statement(table_name, model, record):
    """Generate INSERT statement for a record."""
    columns = []
    values = []
    
    for column in model.__table__.columns:
        columns.append(f'`{column.name}`')
        value = getattr(record, column.name)
        
        if value is None:
            values.append('NULL')
        elif isinstance(value, bool):
            values.append('1' if value else '0')
        elif isinstance(value, (int, float)):
            values.append(str(value))
        elif isinstance(value, datetime):
            values.append(f"'{value.strftime('%Y-%m-%d %H:%M:%S')}'")
        else:
            values.append(f"'{escape_sql_string(str(value))}'")
    
    return f"INSERT INTO `{table_name}` ({', '.join(columns)}) VALUES ({', '.join(values)});"


def escape_sql_string(s):
    """Escape a string for SQL insertion."""
    if s is None:
        return ''
    return s.replace("\\", "\\\\").replace("'", "\\'").replace('"', '\\"').replace('\n', '\\n').replace('\r', '\\r')


def list_backups():
    """
    List all available backups.
    
    Returns:
        dict: {'cert_backups': list, 'db_backups': list}
    """
    backup_path = get_backup_path()
    
    cert_backups = []
    db_backups = []
    
    if os.path.exists(backup_path):
        # Certificate backups
        cert_pattern = os.path.join(backup_path, 'certs_backup_*.zip')
        for f in sorted(glob.glob(cert_pattern), key=os.path.getmtime, reverse=True):
            stat = os.stat(f)
            cert_backups.append({
                'filename': os.path.basename(f),
                'path': f,
                'size': stat.st_size,
                'size_human': format_file_size(stat.st_size),
                'created': datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
            })
        
        # Database backups
        db_pattern = os.path.join(backup_path, 'db_backup_*.sql')
        for f in sorted(glob.glob(db_pattern), key=os.path.getmtime, reverse=True):
            stat = os.stat(f)
            db_backups.append({
                'filename': os.path.basename(f),
                'path': f,
                'size': stat.st_size,
                'size_human': format_file_size(stat.st_size),
                'created': datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
            })
    
    return {
        'cert_backups': cert_backups,
        'db_backups': db_backups,
        'backup_path': backup_path,
        'max_backups': MAX_BACKUPS
    }


def delete_backup(filename):
    """
    Delete a specific backup file.
    
    Args:
        filename: Name of the backup file to delete
        
    Returns:
        dict: {'success': bool, 'message': str}
    """
    backup_path = get_backup_path()
    file_path = os.path.join(backup_path, filename)
    
    # Security check - ensure file is in backup directory
    if not os.path.abspath(file_path).startswith(os.path.abspath(backup_path)):
        return {'success': False, 'message': 'Invalid file path.'}
    
    # Check if file exists and is a backup file
    if not os.path.exists(file_path):
        return {'success': False, 'message': 'Backup file not found.'}
    
    if not (filename.startswith('certs_backup_') or filename.startswith('db_backup_')):
        return {'success': False, 'message': 'Invalid backup file.'}
    
    try:
        os.remove(file_path)
        log.info('Backup deleted: %s', filename)
        return {'success': True, 'message': f'Backup "{filename}" deleted successfully.'}
    except Exception as e:
        log.error('Failed to delete backup %s: %s', filename, e)
        return {'success': False, 'message': f'Failed to delete backup: {str(e)}'}


def format_file_size(size_bytes):
    """Format file size in human-readable format."""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size_bytes < 1024:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.1f} TB"


def run_scheduled_backup(app):
    """
    Run scheduled backup based on settings.
    Called by APScheduler at the configured time.
    
    Args:
        app: Flask application instance
    """
    with app.app_context():
        from models import Setting
        
        # Check if scheduled backup is enabled
        enabled_setting = Setting.query.filter_by(key='backup_schedule_enabled').first()
        if not enabled_setting or enabled_setting.value != 'true':
            log.debug('Scheduled backup is disabled, skipping.')
            return
        
        # Get backup type
        type_setting = Setting.query.filter_by(key='backup_schedule_type').first()
        backup_type = type_setting.value if type_setting else 'both'
        
        log.info('Starting scheduled backup (type: %s)', backup_type)
        
        results = []
        
        # Backup certificates if configured
        if backup_type in ('certs', 'both'):
            try:
                result = backup_certificates()
                if result['success']:
                    log.info('Scheduled certificate backup completed: %s', result['filename'])
                    results.append(('certs', True, result['filename']))
                else:
                    log.error('Scheduled certificate backup failed: %s', result['message'])
                    results.append(('certs', False, result['message']))
            except Exception as e:
                log.error('Scheduled certificate backup error: %s', str(e))
                results.append(('certs', False, str(e)))
        
        # Backup database if configured
        if backup_type in ('db', 'both'):
            try:
                result = backup_database()
                if result['success']:
                    log.info('Scheduled database backup completed: %s', result['filename'])
                    results.append(('db', True, result['filename']))
                else:
                    log.error('Scheduled database backup failed: %s', result['message'])
                    results.append(('db', False, result['message']))
            except Exception as e:
                log.error('Scheduled database backup error: %s', str(e))
                results.append(('db', False, str(e)))
        
        log.info('Scheduled backup completed: %s', results)
        return results


def get_backup_schedule():
    """
    Get backup schedule settings.
    
    Returns:
        dict with schedule settings including frequency, day_of_week, day_of_month
    """
    try:
        from flask import current_app
        from models import Setting
        
        enabled_setting = Setting.query.filter_by(key='backup_schedule_enabled').first()
        time_setting = Setting.query.filter_by(key='backup_schedule_time').first()
        type_setting = Setting.query.filter_by(key='backup_schedule_type').first()
        frequency_setting = Setting.query.filter_by(key='backup_schedule_frequency').first()
        day_of_week_setting = Setting.query.filter_by(key='backup_schedule_day_of_week').first()
        day_of_month_setting = Setting.query.filter_by(key='backup_schedule_day_of_month').first()
        
        enabled = enabled_setting.value == 'true' if enabled_setting else False
        time_str = time_setting.value if time_setting else '02:00'
        backup_type = type_setting.value if type_setting else 'both'
        frequency = frequency_setting.value if frequency_setting else 'daily'
        day_of_week = int(day_of_week_setting.value) if day_of_week_setting else 0
        day_of_month = int(day_of_month_setting.value) if day_of_month_setting else 1
        
        # Parse time
        try:
            hour, minute = map(int, time_str.split(':'))
        except (ValueError, AttributeError):
            hour, minute = 2, 0
        
        # Validate day_of_week (0-6) and day_of_month (1-28)
        day_of_week = max(0, min(6, day_of_week))
        day_of_month = max(1, min(28, day_of_month))
        
        return {
            'enabled': enabled,
            'time': time_str,
            'type': backup_type,
            'frequency': frequency,
            'day_of_week': day_of_week,
            'day_of_month': day_of_month,
            'hour': hour,
            'minute': minute
        }
    except Exception:
        return {
            'enabled': False,
            'time': '02:00',
            'type': 'both',
            'frequency': 'daily',
            'day_of_week': 0,
            'day_of_month': 1,
            'hour': 2,
            'minute': 0
        }
