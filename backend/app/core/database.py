"""
CyberSleuth AI – Database Connection
Member 2: Backend & Data Engineering

Sets up SQLAlchemy engine with PostgreSQL + pgvector extension (or SQLite fallback).
"""
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker, DeclarativeBase
from .config import settings

is_sqlite = settings.DB_URL.startswith("sqlite")

engine_kwargs = {"pool_pre_ping": True}
if is_sqlite:
    engine_kwargs["connect_args"] = {"check_same_thread": False}
else:
    engine_kwargs["pool_size"] = 10
    engine_kwargs["max_overflow"] = 20

engine = create_engine(settings.DB_URL, **engine_kwargs)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Base(DeclarativeBase):
    pass


def get_db():
    """FastAPI dependency – yields a DB session and closes it after the request."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    """Create all tables, enable pgvector (if Postgres), and seed default admin user."""
    try:
        with engine.connect() as conn:
            if engine.dialect.name == "postgresql":
                try:
                    conn.execute(text("CREATE EXTENSION IF NOT EXISTS vector;"))
                    conn.commit()
                except Exception as e:
                    print(f"[Database] Notice: Could not enable vector extension: {e}")

        # Import all models so SQLAlchemy sees them before create_all
        from app.models import user, event, alert, incident  # noqa: F401
        Base.metadata.create_all(bind=engine)

        # Seed default admin user if none exists
        from app.core.security import hash_password
        with SessionLocal() as session:
            admin_user = session.query(user.User).filter(user.User.username == "admin").first()
            if not admin_user:
                admin_user = user.User(
                    username="admin",
                    email="admin@cybersleuth.ai",
                    hashed_pw=hash_password("admin123"),
                    is_admin=True,
                    is_active=True,
                )
                session.add(admin_user)
                session.commit()
                print("[Database] Seeded default admin user: admin / admin123")
    except Exception as e:
        print(f"[Database] Notice: DB connection not available on startup (will initialize when running with DB): {e}")
