import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))


class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', os.urandom(32).hex())
    UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16 MB max upload
    DEFAULT_CERT_PATH = '/etc/pki/tls/certs'

    # Database configuration
    DB_TYPE = os.environ.get('DB_TYPE', 'sqlite')  # 'sqlite' or 'mariadb'

    if DB_TYPE == 'mariadb':
        DB_HOST = os.environ.get('DB_HOST', 'localhost')
        DB_PORT = os.environ.get('DB_PORT', '3306')
        DB_NAME = os.environ.get('DB_NAME', 'certmanager')
        DB_USER = os.environ.get('DB_USER', 'certmanager')
        DB_PASS = os.environ.get('DB_PASS', '')
        SQLALCHEMY_DATABASE_URI = (
            f"mysql+pymysql://{DB_USER}:{DB_PASS}@{DB_HOST}:{DB_PORT}/{DB_NAME}"
        )
    else:
        SQLALCHEMY_DATABASE_URI = (
            'sqlite:///' + os.path.join(BASE_DIR, 'instance', 'certmanager.db')
        )

    SQLALCHEMY_TRACK_MODIFICATIONS = False
