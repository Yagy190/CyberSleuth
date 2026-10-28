"""
Pytest configuration for backend unit tests.
Uses SQLite in-memory database to allow isolated, zero-dependency testing.
"""
import pytest
from datetime import datetime, timezone
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.database import Base, get_db
from app.core.config import settings
from app.main import app
from app.models.user import User
from app.models.event import Event, EventType, GroundTruth
from app.models.alert import Alert, AlertSeverity, AlertStatus
from app.core.security import hash_password, create_access_token

from sqlalchemy.pool import StaticPool

# In-memory SQLite engine with StaticPool so all connections share the same memory DB
TEST_DB_URL = "sqlite:///:memory:"
test_engine = create_engine(
    TEST_DB_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)


@pytest.fixture(scope="function")
def db_session():
    Base.metadata.create_all(bind=test_engine)
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(bind=test_engine)


@pytest.fixture(scope="function")
def client(db_session):
    def override_get_db():
        try:
            yield db_session
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


@pytest.fixture
def auth_headers(db_session):
    user = User(
        username="test_analyst",
        email="analyst@cybersleuth.ai",
        hashed_pw=hash_password("Password123!"),
        is_admin=True,
        is_active=True,
    )
    db_session.add(user)
    db_session.commit()
    token = create_access_token(user.username)
    return {"Authorization": f"Bearer {token}"}
