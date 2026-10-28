import os
import secrets
from datetime import timedelta
from dotenv import load_dotenv

# Cargar variables desde el archivo .env ubicado en la raíz del proyecto
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
load_dotenv(os.path.join(BASE_DIR, ".env"))


class Config:
    """Configuración endurecida bajo estándares OWASP ASVS v4.0."""

    # 1. Clave Secreta Criptográfica (RDS-01 / RS-04 / RS-10)
    SECRET_KEY = os.getenv("FLASK_SECRET_KEY", secrets.token_hex(32))

    # 2. Conexión Segura a PostgreSQL mediante SQLAlchemy + Psycopg2 (RS-08 / RNF-01)
    _raw_db_url = os.getenv(
        "DATABASE_URL",
        "postgresql+psycopg2://atelier_app:AtelierPass#2026!@127.0.0.1:5432/alquiler_disfraces_db",
    )
    if _raw_db_url.startswith("postgres://"):
        _raw_db_url = _raw_db_url.replace("postgres://", "postgresql+psycopg2://", 1)
    elif _raw_db_url.startswith("postgresql://"):
        _raw_db_url = _raw_db_url.replace("postgresql://", "postgresql+psycopg2://", 1)

    SQLALCHEMY_DATABASE_URI = _raw_db_url
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        "pool_pre_ping": True,
        "pool_recycle": 300,
    }

    # 3. Endurecimiento de Cookies de Sesión (RS-04)
    SESSION_COOKIE_NAME = "atelier_session"
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Strict"
    SESSION_COOKIE_SECURE = os.getenv("COOKIE_SECURE", "False").lower() == "true"
    PERMANENT_SESSION_LIFETIME = timedelta(
        minutes=int(os.getenv("SESSION_TIMEOUT_MINUTES", "30"))
    )

    # 4. Protección Anti-CSRF global con Flask-WTF (RS-10)
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = 3600  # 1 hora de validez del token CSRF

    # 5. Límite máximo de payload a 1 MB contra ataques de Denegación de Servicio - DoS (RNF-03)
    MAX_CONTENT_LENGTH = 1 * 1024 * 1024
